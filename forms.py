from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, EmailField
from wtforms.validators import InputRequired, Length

class RegisterForm(FlaskForm):
    '''Makes a form to register'''

    username = StringField('Username', validators=[InputRequired(), Length(max=20)])

    password = PasswordField('Password', validators=[InputRequired()])

    email = StringField('Email', validators=[InputRequired(), Length(max=50)])

    first_name = StringField('First Name', validators=[InputRequired(), Length(max=30)])

    last_name = StringField('Last Name', validators=[InputRequired(), Length(max=30)])

class LoginForm(FlaskForm):

    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])


class FeedbackForm(FlaskForm):

    title = StringField('Enter the title for your feedback', validators=[InputRequired(), Length(max=100)])

    content = StringField('Feedback', validators=[InputRequired()])