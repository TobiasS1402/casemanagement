from flask import Flask, render_template, request, redirect, url_for, flash
from flask_security import Security, current_user, auth_required, hash_password,  \
     SQLAlchemySessionUserDatastore, permissions_accepted, utils, roles_accepted, login_required, LoginForm
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import os
import zipfile
import requests
import shutil
import urllib3

from models import User, Role
from database import db_session, init_db

urllib3.disable_warnings()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'asdasd23r23tg43g'
app.config['SECURITY_PASSWORD_SALT'] = 'sdasd32rf4wefsdvre6745hbf'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SPLUNK_URL'] = 'https://145.100.105.146:8089/services/receivers/stream' # Splunk URL -> need to make this a variable
app.config['SPLUNK_TOKEN'] = 'eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJ0b2JpYXMgZnJvbSBXSU4tTDdRRUk4NThGSEYiLCJzdWIiOiJ0b2JpYXMiLCJhdWQiOiJhdXRvbWF0aWMgZXZ0eCBwcm9jZXNzaW5nIiwiaWRwIjoiU3BsdW5rIiwianRpIjoiZDRhNzc5OTE1NDUxOGZmMDM1MTk1ZTk3ZDFkYmVhMzgwNmMxM2IxOGNiY2NlMzZkNDc0NjU3ZmJjNWQxZjA2NSIsImlhdCI6MTcwNTU3MjMzOSwiZXhwIjoxNzA4MTY0MzM5LCJuYnIiOjE3MDU1NzIzMzl9.oVuE24zGvLYKPwdkurl-fxo2iXl6boeddpU3FxWcgTvFCFRVvAze5zLTZiHPsVANdz8YouyeuQqB8TcEZz7p6w'

app.teardown_appcontext(lambda exc: db_session.close())
user_datastore = SQLAlchemySessionUserDatastore(db_session, User, Role)
app.security = Security(app, user_datastore, register_blueprint=False)


def splunkConfig(evtx,root):
    splunk_url = app.config['SPLUNK_URL']
    splunk_token = app.config['SPLUNK_TOKEN']
    splunk_file_path = os.path.join(root, evtx) # This just makes sure I can find the file again

    headers = {
        'Authorization': 'Bearer ' + splunk_token
    }

    params = { 
        "sourcetype": "preprocess-winevt", # Required for correct processing of eventlogdata
        "index": "main" # The index its being put in -> need to make this a variable
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
        name="admin", permissions={"all"}
    )
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
    return redirect(url_for('login'))

@app.route('/')
@auth_required()
def index():
    return render_template('index.html')

@app.route('/admin')
@auth_required()
@roles_accepted("admin") # Add necessary roles here
def admin():
    existing_users = User.query.all()
    existing_groups = Role.query.all()
    return render_template('admin.html', current_user=current_user, existing_users=existing_users, existing_groups=existing_groups)

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
                        evtx_files.append(file)
                        splunkConfig(file,root)

        if not evtx_files:
            cleanUploads(uploadpath)
            flash('Could not find expected filetype', 'warning')
            return redirect(url_for('index'))
        else:
            cleanUploads()
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