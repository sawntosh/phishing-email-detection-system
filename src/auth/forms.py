from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp


class RegisterForm(FlaskForm):
    # No role field: self-registration always creates an 'analyst' account
    # (see auth/routes.py::register). Letting registrants pick their own
    # role -- including 'admin' -- would be a privilege-escalation hole in
    # the exact RBAC feature this project is graded on. Admin accounts are
    # created only via the .env-seeded default admin (app.py) or a future
    # admin-only promotion action.
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


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])


class TwoFactorForm(FlaskForm):
    token = StringField("6-digit code", validators=[DataRequired(), Length(min=6, max=6)])
