from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, SubmitField, SelectField, BooleanField,
    TextAreaField, HiddenField, IntegerField
)
from wtforms.validators import DataRequired, Length, EqualTo, Email, Optional
from flask import current_app

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')
    
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[Optional(), Email(message='Invalid email address')])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[Optional(), Email()])
    first_name = StringField('First Name', validators=[Optional(), Length(max=50)])
    last_name = StringField('Last Name', validators=[Optional(), Length(max=50)])
    company_name = StringField('Company', validators=[Optional(), Length(max=100)])
    subscription_tier = SelectField(
        'Subscription Tier',
        choices=[('free', 'Free'), ('pro', 'Pro'), ('enterprise', 'Enterprise')],
        validators=[DataRequired()]
    )
    tenant_id = StringField('Tenant ID', validators=[Optional(), Length(max=36)])
    phone = StringField('Phone', validators=[Optional(), Length(max=20)])
    timezone = SelectField(
        'Timezone',
        choices=[('UTC', 'UTC'), ('US/Eastern', 'US/Eastern'), ('US/Central', 'US/Central'), ('US/Mountain', 'US/Mountain'), ('US/Pacific', 'US/Pacific')],
        validators=[DataRequired()]
    )
    password = PasswordField('Password', validators=[Optional()])
    notes = TextAreaField('Notes', validators=[Optional(), Length(max=1000)])
    roles = StringField('Initial Roles (comma separated)', validators=[Optional(), Length(max=200)])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Create User')


class EditUserForm(FlaskForm):
    email = StringField('Email', validators=[Optional(), Email()])
    first_name = StringField('First Name', validators=[Optional(), Length(max=50)])
    last_name = StringField('Last Name', validators=[Optional(), Length(max=50)])
    company_name = StringField('Company', validators=[Optional(), Length(max=100)])
    subscription_tier = SelectField(
        'Subscription Tier',
        choices=[('free', 'Free'), ('pro', 'Pro'), ('enterprise', 'Enterprise')],
        validators=[DataRequired()]
    )
    phone = StringField('Phone', validators=[Optional(), Length(max=20)])
    timezone = SelectField(
        'Timezone',
        choices=[('UTC', 'UTC'), ('US/Eastern', 'US/Eastern'), ('US/Central', 'US/Central'), ('US/Mountain', 'US/Mountain'), ('US/Pacific', 'US/Pacific')],
        validators=[DataRequired()]
    )
    is_active = BooleanField('Active')
    notes = TextAreaField('Notes', validators=[Optional(), Length(max=1000)])
    submit = SubmitField('Save Changes')


class UserInviteForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    roles = StringField('Roles (comma separated)', validators=[Optional(), Length(max=200)])
    submit = SubmitField('Send Invite')


class BulkUserActionForm(FlaskForm):
    action = SelectField('Action', choices=[
        ('assign_role', 'Assign Role'),
        ('deactivate', 'Deactivate'),
        ('reactivate', 'Reactivate'),
        ('update_subscription', 'Change Subscription Tier')
    ], validators=[DataRequired()])
    role = StringField('Role', validators=[Optional(), Length(max=50)])
    subscription_tier = SelectField('Subscription Tier', choices=[('free', 'Free'), ('pro', 'Pro'), ('enterprise', 'Enterprise')], validators=[Optional()])
    user_ids = StringField('User IDs (comma separated)', validators=[DataRequired()])
    submit = SubmitField('Apply')