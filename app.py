from flask import Flask, render_template, request, redirect, url_for, flash
from flask_security import Security, current_user, auth_required, SQLAlchemySessionUserDatastore, utils, roles_accepted, roles_required, permissions_required, permissions_accepted
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
import os
import zipfile
import requests
import shutil
import urllib3
import logging
from models import User, Role, RolesUsers, Case # import from models.py
from database import db_session, init_db # import from database.py

urllib3.disable_warnings() # disable logging warnings

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY") # randomize on deployment
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get("SECURITY_PASSWORD_SALT") # randomize on deployment
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SPLUNK_URL'] = os.environ.get("SPLUNK_URL") # https://[address]:[port]
app.config['SPLUNK_TOKEN'] = os.environ.get("SPLUNK_TOKEN") # bearer token
app.config['ADMIN_PASSWORD'] = os.environ.get("ADMIN_PASSWORD") # custom strong admin password
app.config['ADMIN_EMAIL'] = os.environ.get("ADMIN_EMAIL") # set custom default admin email

app.teardown_appcontext(lambda exc: db_session.close())
user_datastore = SQLAlchemySessionUserDatastore(db_session, User, Role)
app.security = Security(app, user_datastore, register_blueprint=False)
csrf = CSRFProtect(app)
logging.basicConfig(level=logging.INFO)

'''
Delete splunk index: curl -o - -X DELETE -k -u xxx:xxx \
     https://145.100.105.146:8089/services/data/indexes/test4

'''

@app.before_request
def log_authentication_and_authorization():
    if current_user.is_authenticated:
        logging.info(f"User {current_user.username} accessed /{request.endpoint} from {request.remote_addr}")
    else:
        logging.warning("Unauthenticated access attempted.")

class splunkInterface:
    def __init__(self):
        '''Initialization function loading our splunk host and setting the JWT bearer'''
        self.splunk_url = app.config['SPLUNK_URL']
        self.splunk_token = app.config['SPLUNK_TOKEN']
        self.splunk_headers = {
            'Authorization': 'Bearer ' + self.splunk_token
        }

    def create_index(self, index):
        '''Index creation function which passes the custom index name as data to the url endpoint'''
        url = self.splunk_url + "/services/data/indexes"

        data = {
            "name": index
        }

        splunk_request = requests.post(
            url,
            headers=self.splunk_headers,
            data=data,
            verify=False
        )

        if splunk_request.status_code == 201:
            flash(f'Index {index} has been created successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash(f'Index creation has failed with {splunk_request.status_code}', 'danger')
            return redirect(url_for('index'))

    def upload_to_splunk(self, evtx, root, index):
        '''Evidence upload function which passes our file(streams) on our index with the url endpoint'''
        splunk_file_path = os.path.join(root, evtx)

        params = {
            "sourcetype": "preprocess-winevt",
            "index": index
        }

        files = {'data': (evtx, open(splunk_file_path, 'rb'))}

        url = self.splunk_url + "/services/receivers/stream"

        splunk_request = requests.post(
            url,
            params=params,
            headers=self.splunk_headers,
            files=files,
            verify=False
        )

        if splunk_request.status_code == 204:
            flash('File ' + evtx + ' uploaded, unpacked, and sent to Splunk successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('File ' + evtx + ' uploaded, but communication to Splunk failed', 'danger')
            return redirect(url_for('index'))


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


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
        name="admin", description="Manage app with access to admin endpoint", permissions={"view", "upload", "add", "create_user"}
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
        admin_password = app.config['ADMIN_PASSWORD']
        admin_email = app.config['ADMIN_EMAIL']
        #admin_password = "adminpassword" not good
        app.security.datastore.create_user(username='admin',email=admin_email,password=generate_password_hash(admin_password,method='pbkdf2:sha256'),roles=["admin"])
        db_session.commit()
        print('Admin user created successfully with password: ' + str(admin_password))


@app.route('/login', methods=['GET', 'POST'], endpoint='security.login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            utils.login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
            return render_template('login.html')
    return render_template('login.html', form=form)


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


@app.route('/me', methods=['GET', 'POST'])
@auth_required()
def me():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if the current password is correct
        if not check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('change_password'))

        # Check if the new password and confirmation match
        if new_password != confirm_password:
            flash('New password and confirmation do not match.', 'danger')
            return redirect(url_for('change_password'))

        # Update the user's password
        current_user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db_session.commit()

        flash('Password successfully changed!', 'success')
        return redirect(url_for('index'))

    return render_template('profile.html')


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
    email = request.form['email']
    password = request.form['password']
    roles = request.form.getlist('roles')

    # Input validation
    if not email or not username or not password or not roles:
        flash('Please fill out all fields.', 'danger')
        return redirect(url_for('admin'))

    # Check if user with the same username already exists
    existing_user = User.query.filter_by(username=username).first()

    existing_email = User.query.filter_by(email=email).first()

    if existing_user:
        flash(f'A user with the username {username} already exists.', 'danger')
        return redirect(url_for('admin'))

    if existing_email:
        flash(f'A user with the emailaddress {username} already exists.', 'danger')
        return redirect(url_for('admin'))
    
    # Create the new user
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    #new_user = User(username=username, password=hashed_password, roles=roles) #breaks for some reason??
    app.security.datastore.create_user(username=username,email=email,password=hashed_password,roles=roles)

    db_session.commit()
    
    logging.info(f"User {current_user.username} created new user {username} with role {roles} from {request.remote_addr}")

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

    logging.info(f"User {current_user.username} created new role {role} with permissions {permissions} from {request.remote_addr}")

    flash('Role created successfully!', 'success')
    return redirect(url_for('admin'))


@app.route('/case', methods=['POST'])
@auth_required()
@roles_accepted("admin", "user")
def case():
    # Get form data
    name = request.form['name']
    client = request.form['client']
    splunk_index = request.form['splunk_index'].lower()
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

    splunkInterface().create_index(index=splunk_index)
    
    # Create the new case
    new_case = Case(name=name, client=client, splunk_index=splunk_index)

    # Assign users to the case
    assigned_users = User.query.filter(User.id.in_(assigned_users_ids)).all()
    new_case.assigned_users.extend(assigned_users)

    # Add the case to the database
    db_session.add(new_case)
    db_session.commit()

    logging.info(f"User {current_user.username} created new case {name} for {client} from {request.remote_addr}")

    flash('Case created successfully!', 'success')
    return redirect(url_for('dashboard'))


@app.route('/edit_case/<int:case_id>', methods=['GET','POST'])
@auth_required()
@roles_accepted("admin")
def edit_case(case_id):
    existing_case = Case.query.filter_by(id=case_id).first()
    existing_users = User.query.all()

    if request.method == "GET":    
        if not existing_case:
            flash(f'This case does not exist', 'danger')
            return redirect(url_for('dashboard'))
        else:
            pass

    elif request.method == 'POST':
        name = request.form['name']
        client = request.form['client']
        splunk_index = request.form['splunk_index'].lower()
        assigned_users_ids = request.form.getlist('all_users')

        if not existing_case:
            flash(f'This case does not exist', 'danger')
            return redirect(url_for('dashboard'))
        else:
            if not name or not client or not splunk_index or not assigned_users_ids:
                flash('Please fill out all fields.', 'danger')
                return redirect(url_for('dashboard'))
            else:
                existing_case.name = name
                existing_case.client = client
                existing_case.splunk_index = splunk_index

                assigned_users = User.query.filter(User.id.in_(assigned_users_ids)).all()
                existing_case.assigned_users = assigned_users

                db_session.commit()

                logging.info(f"User {current_user.username} updated case {name} for {client} from {request.remote_addr}")
                flash('Case updated successfully!', 'success')

    return render_template('case.html', case=existing_case, existing_users=existing_users)


@app.route('/delete_case/<int:case_id>', methods=['POST'])
@auth_required()
@roles_accepted("admin")
def delete_case(case_id):
    existing_case = Case.query.filter_by(id=case_id).first()
    if not existing_case:
        flash(f'This case does not exist', 'danger')
        return redirect(url_for('dashboard'))
    else:
        db_session.delete(existing_case)
        db_session.commit()
        flash('Case deleted successfully!', 'success')
        flash('Splunk index has not been deleted', 'warning')
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

        logging.info(f"User {current_user.username} uploaded zip to {zip_path} from {request.remote_addr}")

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
                        splunkInterface().upload_to_splunk(evtx=file,root=root,index=splunkIndex)
                        logging.info(f"User {current_user.username} uploaded evidence {file} for {splunkIndex} from {request.remote_addr}")

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
    if os.environ.get("DEPLOYMENT") == "development":
        app.run(debug=True)
    elif os.environ.get("DEPLOYMENT") == "production":
        app.run(debug=False)