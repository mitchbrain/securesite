from flask import Flask, render_template, redirect, session, url_for, flash, make_response, request, \
    send_from_directory
from datetime import timedelta
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import Form
from wtforms import StringField, PasswordField, validators
from wtforms.validators import InputRequired
from flask_sqlalchemy import SQLAlchemy
import os
from os import listdir
from os.path import isfile


app = Flask(__name__)
app.secret_key = os.urandom(34)
app.config['SECRET_KEY'] = 'ZK9urczdv%t9b'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = 'True'
UPLOAD_FOLDER = 'Files'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['FLAWFINDER_PATH'] = 'flawfinder-1.31/flawfinder'
app.config['PMD_PATH'] = 'pmd-bin-5.5.2'
ALLOWED_EXTENSIONS = set(['c', 'cpp', 'jar', 'h'])
db = SQLAlchemy(app)
app.permanent_session_lifetime = timedelta(minutes=15)


class User(db.Model):
    __tablename__ = 'users'
    username = db.Column('username', db.Text, primary_key=True)
    password = db.Column('password', db.Text)

    def __init__(self, username, password):
        self.username = username
        self.password = password


class LoginForm(Form):
    username = StringField('Username', validators=[
        InputRequired(),
        validators.Regexp('^\w+$', message="Username must contain only letters numbers or underscore"),
        validators.Length(min=4, max=25, message="Username must be between 4 & 25 characters")
    ])
    password = PasswordField('Password', validators=[InputRequired()])


class RegistrationForm(Form):
    username = StringField('Username', validators=[
        InputRequired(),
        validators.Regexp('^\w+$', message="Username must contain only letters numbers or underscore"),
        validators.Length(min=4, max=25, message="Username must be between 4 & 25 characters")
    ])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.Length(min=8, max=25, message="Password must be between 8 & 25 characters"),
        validators.EqualTo('confirm', message='Passwords must match'),
    ])
    confirm = PasswordField('Repeat Password')


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def index():
    form = LoginForm()
    if form.validate_on_submit():
        for x in db.session.query(User).all():
            if x.username == form.username.data and check_password_hash(x.password, form.password.data):
                session.permanent = True
                session[form.username.data] = form.username.data
                resp = make_response(get_list_login(form.username.data))
                resp.set_cookie('uh', form.username.data)
                return resp
        flash('Invalid Username or Password')
    return render_template('index.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' and form.validate():
        user = User(form.username.data, generate_password_hash(form.password.data))
        users = db.session.query(User).all()
        for x in users:
            flash('Username Taken')
            if form.username.data in x.username:
                return redirect(url_for('register'))
        else:
            db.session.add(user)
            db.session.commit()
            db.session.flush()
            os.mkdir(os.path.join(app.config['UPLOAD_FOLDER'], form.username.data))
            return redirect('/')
    return render_template('register.html', form=form)


@app.route('/logout/<username>', methods=['GET', 'POST'])
def logout(username):
    if username in session and session[username] == username and request.method == 'POST':
        session.pop(username, None)
        return 'Logged Out <meta http-equiv="refresh" content="3;/" />'
    return redirect(url_for('index'))


@app.route('/profile/<username>', methods=['GET', 'POST'])
def profile(username):
    if username in session and session[username] == username and session[username] == request.cookies.get('uh'):
        file_list = get_files(username)
        num_file=len(file_list)
        if request.method == 'POST':
            # check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part')
                return redirect(url_for('profile', username=session[username], file_list=file_list))
            file = request.files['file']
            # if user does not select file, browser also
            # submits an empty part without filename
            if file.filename == '':
                flash('No selected file')
                return redirect(url_for('profile', username=session[username], file_list=file_list))
            if file and allowed_file(file.filename) and num_file < 10:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], session[username], filename))
                flash('Upload Successful!')
                analyze(os.path.join(app.config['UPLOAD_FOLDER'], session[username]), filename)
                return redirect(url_for('profile', username=session[username], file_list=file_list))
        else:
            return render_template('profile.html', username=session[username], file_list=file_list)
    return redirect(url_for('index'))


@app.route('/profile/<username>/<file>')
def download(username, file):
    if username in session and session[username] == username and session[username] == request.cookies.get('uh'):
        return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER'], session[username]), file)


def get_files(username):
    if username in session and session[username] == username and session[username] == request.cookies.get('uh'):
        path = os.path.join(app.config['UPLOAD_FOLDER'], session[username])
        return [file for file in listdir(path) if(isfile(os.path.join(path, file)))]


def get_list_login(username):
    if username in session and session[username] == username and session[username]:
        file_list = get_files(username)
        return render_template('profile.html', username=session[username], file_list=file_list)


def analyze(filepath, file):
    input = os.path.join(filepath, file)
    filetot = file.rsplit('.', 1)
    output = os.path.join(filepath, filetot[0])
    file_type = filetot[1]
    os.system(app.config['FLAWFINDER_PATH'] + " " + input + " |tee " + output + ".txt 2>&1")


if __name__ == '__main__':
    app.run(debug=True)