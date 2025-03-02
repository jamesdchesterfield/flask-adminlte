# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from flask import render_template, redirect, request, url_for
from flask_login import (
    current_user,
    login_user,
    logout_user
)

from apps import db, login_manager
from apps.authentication import blueprint
from apps.authentication.forms import LoginForm, CreateAccountForm, LockScreenForm
from apps.authentication.models import Users

from apps.authentication.util import verify_pass


@blueprint.route('/')
def route_default():
    return redirect(url_for('authentication_blueprint.login'))


# Login & Registration

@blueprint.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if 'login' in request.form:

        # read form data
        username = request.form['username']
        password = request.form['password']

        # Locate user
        user = Users.query.filter_by(username=username).first()

        # Check the password
        if user and verify_pass(password, user.password):

            login_user(user)
            return redirect(url_for('authentication_blueprint.route_default'))

        # Something (user or pass) is not ok
        return render_template('accounts/login.html',
                               msg='Wrong user or password',
                               form=login_form)

    if not current_user.is_authenticated:
        return render_template('accounts/login.html',
                               form=login_form)
    return redirect(url_for('home_blueprint.index'))


@blueprint.route('/lockscreen', methods=['GET', 'POST'])
def lockscreen():
    lockscreen_form = LockScreenForm(request.form)
   
    if request.method == "POST":
        password = request.form.get('password')
        user = current_user
 
    #if 'unlock' in request.form:
        #password = request.form['password']
        #user = current_user  # Get the currently logged-in user

        # Verify if the entered password is correct
        if user and verify_pass(password, user.password):
            return redirect(url_for('home_blueprint.index'))  # Redirect back to dashboard
            print("got here")
            #return redirect(url_for('authentication_blueprint.route_default'))

        return render_template('home/examples-lockscreen.html',
                               form=lockscreen_form)

    return render_template('home/examples-lockscreen.html', form=lockscreen_form)


@blueprint.route('/register', methods=['GET', 'POST'])
def register():
    print("register method accessed")
    create_account_form = CreateAccountForm(request.form)
    if 'register' in request.form:

        username = request.form['username']
        email = request.form['email']

        # Check usename exists
        user = Users.query.filter_by(username=username).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Username already registered',
                                   success=False,
                                   form=create_account_form)

        # Check email exists
        user = Users.query.filter_by(email=email).first()
        if user:
            return render_template('accounts/register.html',
                                   msg='Email already registered',
                                   success=False,
                                   form=create_account_form)

        # else we can create the user
        user = Users(**request.form)
        db.session.add(user)
        db.session.commit()

        return render_template('accounts/register.html',
                               msg='User created please <a href="/login">login</a>',
                               success=True,
                               form=create_account_form)

    else:
        return render_template('accounts/register.html', form=create_account_form)


@blueprint.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('authentication_blueprint.login'))


# Errors

#@login_manager.unauthorized_handler
#def unauthorized_handler():
#    return render_template('home/page-403.html'), 403


#@blueprint.errorhandler(403)
#def access_forbidden(error):
#    return render_template('home/page-403.html'), 403


#@blueprint.errorhandler(404)
#def not_found_error(error):
#    return render_template('home/page-404.html'), 404


@blueprint.errorhandler(500)
def internal_error(error):
    return render_template('home/page-500.html'), 500
