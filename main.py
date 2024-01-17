from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import zipfile

app = Flask(__name__)
app.config['SECRET_KEY'] = 'asdasd23r23tg43g'
app.config['UPLOAD_FOLDER'] = 'uploads'

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Example user class (replace with your own User class if you have one)
class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = generate_password_hash(password, method='pbkdf2')

# Example user database (replace with your own user database)
users = [
    User(1, 'admin', 'adminpassword'),
    User(2, 'tobias', 'tobiaspassword')
]

@login_manager.user_loader
def load_user(user_id):
    return next((user for user in users if user.id == int(user_id)), None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = next((user for user in users if user.username == username and check_password_hash(user.password, password)), None)
        if user:
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
@login_required
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
        zip_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(zip_path)

        uploadpath = os.path.join(app.config['UPLOAD_FOLDER'], current_user.username)
        evtx_files = [] 

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(uploadpath)
            for root, dirs, files in os.walk(uploadpath):
                for file in files:
                    if not file.endswith('.evtx'):
                        os.unlink(os.path.join(root, file) ) #could be very dangerous
                    else:
                        evtx_files.append(file)
        if evtx_files: 
            '''
                Here we need to write code in order to process and input our .evtx files into Splunk            
            '''
            flash('File uploaded and unpacked successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Could not find expected filetype', 'warning')
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