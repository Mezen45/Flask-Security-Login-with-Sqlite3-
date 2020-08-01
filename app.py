from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required, current_user, roles_accepted
from sqlalchemy.orm import relationship, backref
from sqlalchemy import Boolean, DateTime, Column, Integer, \
    String, ForeignKey
from flask import abort, request
from flask_security.forms import RegisterForm
from wtforms import StringField
from datetime import timedelta
from flask import session, app, redirect, url_for, Response
from flask import *
import sqlite3
from flask_bootstrap import Bootstrap
from authy.api import AuthyApiClient


ALLOWED_IPS = ['192.168.0.73', '127.0.0.1', '192.168.1.13']


# some Configurations

app = Flask(__name__)
bootstrap = Bootstrap(app)

app.config.from_object('config')

app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'asecretkey'
app.config['SECURITY_REGISTERABLE'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////home/R_admin/Desktop/MPSOFTLOGIN/shadymp.db'
app.config['SECURITY_USER_IDENTITY_ATTRIBUTES'] = ('username', 'email')
app.config['SECURITY_PASSWORD_SALT'] = 'MPSHADU'
app.config['SECURITY_SEND_REGISTER_EMAIL'] = False
app.config['SECURITY_TRACKABLE'] = True
app.config['SECURITY_DEFAULT_REMEMBER_ME'] = False
app.config['SECURITY_REGISTER_USER_TEMPLATE'] = 'security/register_user.html'
app.config['SECURITY_POST_LOGIN_VIEW'] = 'security/verify.html'
app.config['AUTHY_API_KEY'] = "XrkT4DSBnc4Dab6RSwOoF5MJ4riWngLT"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECURITY_LOGIN_URL'] = '/'
# this is your models here

db = SQLAlchemy(app)
roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(),
                                 db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(255), unique=True)
    lastname = db.Column(db.String(255), unique=True)
    codes = db.Column(db.String(8), unique=True)
    email = db.Column(db.String(255), unique=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    phone_number = db.Column(db.String(10), unique=True)
    current_login_at = db.Column(db.DateTime())
    last_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(100))
    current_login_ip = db.Column(db.String(100))
    login_count = db.Column(Integer)
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))


user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

# and the views


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)


@app.errorhandler(403)
def permission_error(e):
    return render_template('403.html', error_code=403), 403


@app.before_request
def limit_remote_addr():
    client_ip = str(request.remote_addr)
    valid = False
    for ip in ALLOWED_IPS:
        if client_ip.startswith(ip) or client_ip == ip:
            valid = True
            break
    if not valid:
        abort(403)


@app.route('/register/', methods=['GET', 'POST'])
def register():
    return render_template('security/register_user.html')

# @app.route('/')
# @login_required
# def index():
#    if current_user.has_role('admin'):
#        return render_template('dashboard.html')

    # admin_role = user_datastore.find_or_create_role('admin')
    # user_datastore.add_role_to_user(current_user, admin_role)
    # db.session.commit()

#    return '<h1> this is protected your email is: {} </h1>'.format(current_user.email)


@app.route('/roleprotected')
@roles_accepted('admin')
def roleprotected():
    return '<h1> this is for Admins you  have no authority to access here '


@app.route("/view")
@roles_accepted('admin')
def view():
    con = sqlite3.connect("shadymp.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("select * from user")
    rows = cur.fetchall()
    return render_template("view.html", rows=rows)


# @app.route('/assign/')
# @roles_accepted('admin')
# def funy():
#    admin_role = user_datastore.find_or_create_role('admin')
#    user_datastore.add_role_to_user(current_user, admin_role)
#    db.session.commit()
#    return render_template('index.html')

'''
@app.route("/verify", methods=["GET", "POST"])
@login_required
def verify():
      country_code = "+216"
      phone_number = "97601525"

      session['country_code'] = country_code
      session['phone_number'] = phone_number

      api.phones.verification_start(phone_number, country_code)

      if request.method == "POST":
         token = request.form.get("token")

         phone_number = session.get("phone_number")
         country_code = session.get("country_code")

         verification = api.phones.verification_check(phone_number,
                                                     country_code,
                                                     token)

         if verification.ok():
           return Response("<h1>Success!</h1>")


      return render_template('security/verify.html')

'''

#@app.route("/")
#@login_required
#def index():
#    return render_template('security/verify.html')









if __name__ == '__main__':
    app.run(host='0.0.0.0')
