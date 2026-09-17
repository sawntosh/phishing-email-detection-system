from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp


class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(3, 80)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=10, message="Password must be at least 10 characters."),
            Regexp(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).+$",
                   message="Password must include upper case, lower case, and a digit."),
        ],
    )
    confirm_password = PasswordField("Confirm password", validators=[DataRequired(), EqualTo("password")])
    role = SelectField("Role", choices=[("analyst", "Analyst"), ("admin", "Admin")], default="analyst")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


class TwoFactorForm(FlaskForm):
    token = StringField("6-digit code", validators=[DataRequired(), Length(min=6, max=6)])
