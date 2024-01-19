from flask import Flask, render_template, request, redirect, url_for, flash
from flask_security import Security, current_user, auth_required,SQLAlchemySessionUserDatastore, utils, roles_accepted, roles_required, permissions_required, permissions_accepted
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import os
import zipfile
import requests
import shutil
import urllib3

from models import User, Role, RolesUsers, Case # import from models.py
from database import db_session, init_db # import from database.py

urllib3.disable_warnings() # disable logging warnings

app = Flask(__name__)
app.config['SECRET_KEY'] = 'asdasd23r23tg43g' # randomize on deployment
app.config['SECURITY_PASSWORD_SALT'] = 'sdasd32rf4wefsdvre6745hbf' # randomize on deployment
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SPLUNK_URL'] = 'https://145.100.105.146:8089/services/receivers/stream' # Splunk URL -> need to make this a variable
app.config['SPLUNK_TOKEN'] = 'eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJ0b2JpYXMgZnJvbSBXSU4tTDdRRUk4NThGSEYiLCJzdWIiOiJ0b2JpYXMiLCJhdWQiOiJhdXRvbWF0aWMgZXZ0eCBwcm9jZXNzaW5nIiwiaWRwIjoiU3BsdW5rIiwianRpIjoiZDRhNzc5OTE1NDUxOGZmMDM1MTk1ZTk3ZDFkYmVhMzgwNmMxM2IxOGNiY2NlMzZkNDc0NjU3ZmJjNWQxZjA2NSIsImlhdCI6MTcwNTU3MjMzOSwiZXhwIjoxNzA4MTY0MzM5LCJuYnIiOjE3MDU1NzIzMzl9.oVuE24zGvLYKPwdkurl-fxo2iXl6boeddpU3FxWcgTvFCFRVvAze5zLTZiHPsVANdz8YouyeuQqB8TcEZz7p6w'

app.teardown_appcontext(lambda exc: db_session.close())
user_datastore = SQLAlchemySessionUserDatastore(db_session, User, Role)
app.security = Security(app, user_datastore, register_blueprint=False)


def splunkConfig(evtx,root,index):
    splunk_url = app.config['SPLUNK_URL']
    splunk_token = app.config['SPLUNK_TOKEN']
    splunk_file_path = os.path.join(root, evtx) # This just makes sure I can find the file again

    headers = {
        'Authorization': 'Bearer ' + splunk_token # Bearer auth with splunk
    }

    params = { 
        "sourcetype": "preprocess-winevt", # Required for correct processing of eventlogdata
        "index": index # The index its being put in -> need to make this a variable
    }

    files = {'data': (evtx, open(splunk_file_path, 'rb'))} # Get filename for source and read the actual file

    splunkRequest = requests.post(splunk_url, params=params, headers=headers, files=files, verify=False) # send the request (looped) to splunk

    if splunkRequest.status_code == 204:
        flash('File '+ evtx + ' uploaded, unpacked and sent to splunk successfully!', 'success')
        return redirect(url_for('index'))
    else:
        flash('File '+ evtx + ' uploaded, but communication to splunk failed', 'danger')
        return redirect(url_for('index'))


def cleanUploads(uploadPath):
    for root, dir, files in os.walk(uploadPath):
        for file in files:
            os.unlink(os.path.join(root,file))
        shutil.rmtree(root)
    return


with app.app_context():
    '''
    Method to initiate the user database and create an admin user with the password "adminpassword".
    Uses User class from models.py
    '''
    init_db()
    app.security.datastore.find_or_create_role(
        name="admin", description="Manage app with access to admin endpoint", permissions={"all"}
    )
    db_session.commit() 

    app.security.datastore.find_or_create_role(
        name="client", description="View and upload cases", permissions={"view", "upload"}
    )
    db_session.commit() 

    app.security.datastore.find_or_create_role(
        name="user", description="View, upload and add cases", permissions={"view", "upload", "add"}
    )
    db_session.commit() 

    admin_user = User.query.filter_by(username='admin').first()
    db_session.commit() 

    if not admin_user:
        admin_password = "adminpassword"
        app.security.datastore.create_user(username='admin',password=generate_password_hash(admin_password,method='pbkdf2:sha256'),roles=["admin"])
        db_session.commit()
        print('Admin user created successfully with password: ' + str(admin_password))


@app.route('/login', methods=['GET', 'POST'], endpoint='security.login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            utils.login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
            return render_template('login.html')
    return render_template('login.html')


@app.route('/logout')
@auth_required()
def logout():
    utils.logout_user()
    flash('Logged out successfully.', 'primary')
    return redirect(url_for('security.login'))


@app.route('/')
@auth_required()
def index():
    existing_users = User.query.all()
    return render_template('index.html', existing_users=existing_users)


@app.route('/dashboard', methods=['POST','GET'])
@auth_required()
@roles_accepted("user","admin","client")
def dashboard():
    cases_users = Case.query.all()
    existing_users = User.query.all()
    return render_template('dashboard.html', cases_users=cases_users, existing_users=existing_users)

@app.route('/user', methods=['POST'])
@auth_required()
@roles_accepted("admin")
def user():
    # Get form data
    username = request.form['username']
    password = request.form['password']
    roles = request.form.getlist('roles')

    # Input validation
    if not username or not password or not roles:
        flash('Please fill out all fields.', 'danger')
        return redirect(url_for('admin'))

    # Check if user with the same username already exists
    existing_user = User.query.filter_by(username=username).first()

    if existing_user:
        flash(f'A user with the username {username} already exists.', 'danger')
        return redirect(url_for('admin'))

    # Create the new user
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    #new_user = User(username=username, password=hashed_password, roles=roles) #breaks for some reason??
    app.security.datastore.create_user(username=username,password=hashed_password,roles=roles)

    db_session.commit()

    flash('User created successfully!', 'success')
    return redirect(url_for('admin'))


@app.route('/role', methods=['POST'])
@auth_required()
@roles_accepted("admin")
def role():
    # Get form data
    role_name = request.form['role']
    description = request.form['description']
    permissions = request.form['permissions']

    # Input validation
    if not role_name or not description or not permissions:
        flash('Please fill out all fields.', 'danger')
        return redirect(url_for('admin'))

    # Check if role with the same name already exists
    existing_role = Role.query.filter_by(name=role_name).first()
    if existing_role:
        flash(f'A role with the name {role_name} already exists.', 'danger')
        return redirect(url_for('admin'))

    # Create the new role
    app.security.datastore.create_role(name=role_name, description=description, permissions=permissions)
    db_session.commit()

    flash('Role created successfully!', 'success')
    return redirect(url_for('admin'))


@app.route('/case', methods=['POST'])
@auth_required()
def case():
    # Get form data
    name = request.form['name']
    client = request.form['client']
    splunk_index = request.form['splunk_index']
    assigned_users_ids = request.form.getlist('assigned_users')  # Handle multiple assigned users

    # Input validation
    if not name or not client or not splunk_index or not assigned_users_ids:
        flash('Please fill out all fields.', 'danger')
        return redirect(url_for('admin'))

    # Check if the case with the same name already exists
    existing_case = Case.query.filter_by(name=name).first()
    if existing_case:
        flash(f'A case with the name {name} already exists.', 'danger')
        return redirect(url_for('admin'))

    # Create the new case
    new_case = Case(name=name, client=client, splunk_index=splunk_index)

    # Assign users to the case
    assigned_users = User.query.filter(User.id.in_(assigned_users_ids)).all()
    new_case.assigned_users.extend(assigned_users)

    # Add the case to the database
    db_session.add(new_case)
    db_session.commit()

    flash('Case created successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin', methods=['GET','POST'])
@auth_required()
@roles_accepted("admin") # Add necessary roles here
def admin():
    existing_users = User.query.all()
    existing_roles = Role.query.all()
    roles_users = RolesUsers.query.all()
    cases_users = Case.query.all()
    return render_template('admin.html', current_user=current_user, existing_users=existing_users, existing_roles=existing_roles, roles_users=roles_users, cases_users=cases_users)

@app.route('/upload', methods=['POST'])
@auth_required()
def upload():
    '''
    This route is for uploading zip files with a specific extension. It unpacks it with a relatively safe extractall() and then discards all the files that 
    are not like .evtx.
    '''
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)
    
    file = request.files['file']

    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(request.url)

    if file and file.filename.endswith('.zip'):
        os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], current_user.username), exist_ok=True)
        zip_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username, secure_filename(file.filename))
        file.save(zip_path)

        uploadpath = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
        evtx_files = [] 

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(uploadpath)
            for root, dir, files in os.walk(uploadpath):
                for file in files:
                    if not file.endswith('.evtx'):
                        os.unlink(os.path.join(root, file)) # could be very dangerous
                    else:
                        splunkIndex = request.form['case'] # pass the right index which belongs to a case
                        evtx_files.append(file)
                        splunkConfig(file,root,splunkIndex)

        if not evtx_files:
            cleanUploads(uploadpath)
            flash('Could not find expected filetype', 'warning')
            return redirect(url_for('index'))
        else:
            cleanUploads(uploadpath)
            return redirect(url_for('index'))
        
    else:
        flash('Invalid file format. Please upload a .zip file.', 'danger')
        return redirect(url_for('index'))

'''
    An API endpoint would also be nice where you can authenticate
'''

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)