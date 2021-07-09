from enum import unique
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, RecaptchaField
from werkzeug.exceptions import default_exceptions
from wtforms import StringField, SubmitField, TextAreaField, PasswordField, BooleanField, DateTimeField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, URL as URLval
import requests
import re
from datetime import datetime, timedelta
from itsdangerous import URLSafeTimedSerializer, TimedJSONWebSignatureSerializer as Serializer
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate, current
from flask_mail import Message, Mail
from urllib.parse import urlparse
from ast import literal_eval as le
from uuid import uuid4 as uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = '09c4a587537f4059549a8f9ef485f284'
app.config['SECURITY_PASSWORD_SALT'] = '763fc88aac5bc2d8df654d351119ed39'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LcVOwobAAAAAFIk9sCMke7fG6bFySp4spGSF_vf'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LcVOwobAAAAAI2qx_g9Uv1rvyF_YIryRgAUHFC1'
app.config['MAIL_SERVER'] = "smtp.googlemail.com"
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'bouncybird.mailsender@gmail.com'
app.config['MAIL_PASSWORD'] = 'asdfghjkl!@#$%^&*()'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=500)
mail = Mail()
bcrypt = Bcrypt()
login_manager = LoginManager()
login_manager.login_message_category = 'info'
mail.init_app(app)
bcrypt.init_app(app)
login_manager.init_app(app)
migrate = Migrate(app, db, render_as_batch=True)


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(
            token,
            salt=app.config['SECURITY_PASSWORD_SALT'],
            max_age=expiration
        )
    except:
        return False
    return email


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    #urls = db.relationship('URL', backref='author', lazy=True)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    staff = db.Column(db.Boolean, nullable=False, default=False)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.confirmed}')"


class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.Text, nullable=False)
    options = db.Column(db.Text, nullable=False)
    votes = db.Column(db.Text, nullable=False)
    unique_id = db.Column(db.Text, nullable=False)
    multiplesubs = db.Column(db.Boolean, nullable=False)


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
                           DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=8, max=30)])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), Length(min=8, max=30), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):

        user = User.query.filter_by(username=username.data).first()

        if user:
            raise ValidationError(
                'That username is taken. Please choose a different username.')

    def validate_email(self, email):

        user = User.query.filter_by(email=email.data).first()

        if user:
            raise ValidationError(
                'That email is taken. Please choose a different email.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=8, max=30)])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):

        user = User.query.filter_by(email=email.data).first()

        if user is None:
            raise ValidationError(
                'There is no account with that email. You must register first.')


class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=8, max=30)])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), Length(min=8, max=30), EqualTo('password')])
    submit = SubmitField('Reset Password')


class PollForm(FlaskForm):
    question = StringField('Question/Title', validators=[DataRequired()])
    options = TextAreaField('Options(Seperate by ||)',
                            validators=[DataRequired()])
    multiplesubs = BooleanField('Allow multiple submissions by one browser')
    recaptcha = RecaptchaField()
    submit = SubmitField('Create Poll')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET', 'POST'])
def home():
    form = PollForm()
    if form.validate_on_submit():
        li = []
        for _ in range(len(form.options.data.split('||'))):
            li.append(0)
        uid = str(uuid())
        while(bool(Poll.query.filter_by(unique_id=uid).first())):
            uid = str(uuid())
        poll = Poll(question=form.question.data,
                    options=form.options.data, multiplesubs=form.multiplesubs.data, votes=str(li), unique_id=uid)
        db.session.add(poll)
        db.session.commit()
        flash(
            f'Your poll has been created! It can be accessed at: <a href="{request.host_url}poll/{poll.id}" target="_blank">{request.host_url}poll/{poll.id}</a>', 'success')
    return render_template('home.html', form=form)


@app.route('/poll/<int:id>')
def poll(id):
    poll = Poll.query.filter_by(id=id).first_or_404()
    return render_template('poll.html', poll=poll, le=le, id=id)


@app.route('/poll/<id>/vote', methods=['POST'])
def vote(id):
    poll = Poll.query.filter_by(id=id).first_or_404()
    if session.get(f'voted:{poll.unique_id}') and poll.multiplesubs == False:
        flash('You have already voted', 'warning')
    else:
        options = poll.options.split('||')
        vote = request.form.get('vote')
        votes = le(poll.votes)
        votes[options.index(vote)] += 1
        poll.votes = str(votes)
        db.session.add(poll)
        db.session.commit()
        if not poll.multiplesubs:
            session[f'voted:{poll.unique_id}'] = True
            session.permanent = True
        flash('You have successfully voted!', 'success')
    return redirect(url_for('poll', id=id))


@app.route('/manage')
def manage():
    polls = Poll.query.all()
    return render_template('manage.html', polls=polls, le=le)


@app.route("/poll/<id>/delete", methods=['POST', 'GET'])
def delete_poll(id):
    poll = Poll.query.get_or_404(id)
    '''if url.author != current_user and current_user.staff == False:
        abort(403)'''
    db.session.delete(poll)
    db.session.commit()
    flash('Your poll has been deleted!', 'success')
    return redirect(url_for('manage'))


def send_confirm_email(user, token, confirm_url):
    msg = Message('Confirm Account', sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To confirm your account, visit the following link:
{url_for('confirm_email', token=token, _external=True)}

This link will expire in 1 hour for security reasons

'''
    mail.send(msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        flash("You are already logged in", "info")
        return redirect(url_for("home"))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(
            form.password.data).decode("utf-8")
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password,
            confirmed=False,
            staff=False
        )
        db.session.add(user)
        db.session.commit()
        token = generate_confirmation_token(user.email)
        confirm_url = url_for("confirm_email",
                              token=token, _external=True)
        send_confirm_email(user, token, confirm_url)
        flash("An email has been sent to confirm your email", "info")
        return redirect(url_for("home"))
    return render_template("register.html", title="Register", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        flash("You are already logged in", "info")
        return redirect(url_for("home"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user.confirmed:
            token = generate_confirmation_token(user.email)
            confirm_url = url_for("confirm_email",
                                  token=token, _external=True)
            send_confirm_email(user, token, confirm_url)
            flash("An email has been sent to confirm your email", "info")
            return redirect(url_for("home"))
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get("next")
            flash("Login Successful. You have been logged in.", "success")
            return redirect(next_page) if next_page else redirect(url_for("home"))
        else:
            flash("Login Unsuccessful. Please check email and password", "danger")
    return render_template("login.html", title="Login", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('reset_token', token=token, _external=True)}

This link will expire in 30 minutes for security reasons

If you did not make this request simply ingore this email and no changes will be made.
'''
    mail.send(msg)


@app.route("/reset_password", methods=["GET", "POST"])
def reset_request():
    if current_user.is_authenticated:
        flash("You are already logged in", "info")
        return redirect(url_for("home"))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash("An email has been sent with instructions to reset your password", "info")
        return redirect(url_for("login"))
    return render_template("reset_request.html", title="Reset Password", form=form)


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_token(token):
    if current_user.is_authenticated:
        flash("You are already logged in", "info")
        return redirect(url_for("home"))
    user = User.verify_reset_token(token)
    if user is None:
        flash("That is an invalid or expired token", "warning")
        return redirect(url_for("reset_request"))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode(
            "utf-8"
        )
        user.password = hashed_password
        db.session.commit()
        flash("Your password has been changed. You are now able to login.", "success")
        return redirect(url_for("login"))
    return render_template("reset_token.html", title="Reset Password", form=form)


@app.route("/confirm/<token>")
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash("The confirmation link is invalid or has expired.", "warning")
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash("Account already confirmed. Please login.", "success")
    else:
        user.confirmed = True
        db.session.add(user)
        db.session.commit()
        flash("You have confirmed your account. Thanks!", "success")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)
