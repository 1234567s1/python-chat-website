from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from main import Users
from validate_email import validate_email


class RegisterationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=8, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    cpassword = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = Users.query.filter_by(usrname=username.data).first()
        if user:
            raise ValidationError('This username already exists')

    def valid_email(self, email):
        user = Users.query.filter_by(email=email.data).first()
        is_valid = validate_email(
            email_address=email.data,
            check_format=True,
            check_blacklist=True,
            check_dns=True,
            dns_timeout=10,
            check_smtp=False,
            smtp_timeout=10, )
        if user:
            raise ValidationError('This email already exists')
        elif not is_valid:
            raise ValidationError('This email does not exist or cannot be accepted, please use another email.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Length(min=1, max=100)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class VerifyForm(FlaskForm):
    code = StringField('Verification Code')
    submit = SubmitField('Submit')


class SearchFriend(FlaskForm):
    name = StringField('Friend Username', validators=[Length(min=2, max=64)])
    submit = SubmitField('Submit')


class GroupName(FlaskForm):
    name = StringField('Group Name', validators=[DataRequired(), Length(min=1, max=64)])
    submit = SubmitField('Submit')
