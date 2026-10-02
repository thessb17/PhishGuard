"""Flask-WTF forms.

Using WTForms gives every state-changing HTML form CSRF protection plus
server-side validation that runs before any business logic executes.
"""

from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField, DateField, PasswordField, SelectField, SelectMultipleField,
    StringField, SubmitField, TextAreaField,
)
from wtforms.validators import (
    DataRequired, Email, EqualTo, Length, Optional, Regexp, ValidationError,
)

from app.models.campaign import CampaignStatus, Difficulty
from app.models.user import Role
from app.services.simulation_templates import template_choices


class LoginForm(FlaskForm):
    username = StringField("Username or email", validators=[DataRequired(), Length(max=320)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=256)])
    remember = BooleanField("Keep me signed in")
    submit = SubmitField("Sign in")


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[
        DataRequired(), Length(min=3, max=64),
        Regexp(r"^[A-Za-z0-9._\-]+$", message="Letters, numbers, dots, dashes and underscores only."),
    ])
    full_name = StringField("Full name", validators=[DataRequired(), Length(max=120)])
    email = StringField("Email", validators=[DataRequired(), Email(), Length(max=320)])
    department = StringField("Department", validators=[Optional(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=10, max=256)])
    confirm = PasswordField("Confirm password", validators=[
        DataRequired(), EqualTo("password", message="Passwords must match."),
    ])
    submit = SubmitField("Create demo account")

    def validate_password(self, field):  # noqa: D401 - WTForms hook
        from app.utils.validators import ValidationError as AppValidationError, validate_password

        try:
            validate_password(field.data)
        except AppValidationError as exc:
            raise ValidationError(exc.message) from exc


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired()])
    new_password = PasswordField("New password", validators=[DataRequired(), Length(min=10, max=256)])
    confirm = PasswordField("Confirm new password", validators=[
        DataRequired(), EqualTo("new_password", message="Passwords must match."),
    ])
    submit = SubmitField("Update password")

    def validate_new_password(self, field):
        from app.utils.validators import ValidationError as AppValidationError, validate_password

        try:
            validate_password(field.data)
        except AppValidationError as exc:
            raise ValidationError(exc.message) from exc


class CampaignForm(FlaskForm):
    name = StringField("Campaign name", validators=[DataRequired(), Length(min=3, max=160)])
    description = TextAreaField("Description", validators=[Optional(), Length(max=2000)])
    template_key = SelectField("Simulation template", validators=[DataRequired()])
    difficulty = SelectField("Difficulty", choices=[(d, d.title()) for d in Difficulty.ALL],
                             default=Difficulty.MEDIUM, validators=[DataRequired()])
    status = SelectField("Status", choices=[(s, s.title()) for s in
                                            (CampaignStatus.DRAFT, CampaignStatus.ACTIVE)],
                         default=CampaignStatus.ACTIVE, validators=[DataRequired()])
    start_date = DateField("Start date", validators=[Optional()])
    end_date = DateField("End date", validators=[Optional()])
    targets = SelectMultipleField("Demo participants", coerce=int, validators=[DataRequired()])
    submit = SubmitField("Launch simulation campaign")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.template_key.choices = template_choices()

    def validate_end_date(self, field):
        if field.data and self.start_date.data and field.data < self.start_date.data:
            raise ValidationError("End date cannot be earlier than the start date.")


class EmailAnalysisForm(FlaskForm):
    sender = StringField("Sender address", validators=[Optional(), Length(max=320)])
    subject = StringField("Subject", validators=[Optional(), Length(max=512)])
    body = TextAreaField("Message body", validators=[DataRequired(), Length(min=10, max=50000)])
    urls = TextAreaField("Additional URLs (one per line)", validators=[Optional(), Length(max=8000)])
    headers = TextAreaField("Raw headers (optional)", validators=[Optional(), Length(max=20000)])
    submit = SubmitField("Analyse email")


class URLAnalysisForm(FlaskForm):
    url = StringField("URL to analyse", validators=[DataRequired(), Length(max=2048)])
    submit = SubmitField("Analyse URL")


class RoleChangeForm(FlaskForm):
    user_id = StringField("User", validators=[DataRequired()])
    role = SelectField("Role", choices=[(r, Role.LABELS[r]) for r in Role.ALL],
                       validators=[DataRequired()])
    submit = SubmitField("Update role")


class SimpleActionForm(FlaskForm):
    """CSRF-protected form for single-button POST actions."""

    submit = SubmitField("Confirm")
