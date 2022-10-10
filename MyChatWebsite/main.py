from enum import unique
import functools
from flask import Flask, render_template, url_for, request, redirect, flash, make_response, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, send, emit, disconnect, join_room, leave_room
from datetime import datetime, timedelta
import random
import hashlib
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from sqlalchemy.dialects.mysql import LONGTEXT
import secrets
import forms
from email_verify import send_verification
import json
import os

pepper = os.environ.get('pepper')
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('database_uri')
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
socketio = SocketIO(app)
db = SQLAlchemy(app)
quantity = 20


#classes for sql database
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    usrname = db.Column(db.String(32), nullable=False, unique=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    usrpasswordhash = db.Column(db.String(128), nullable=False)
    usrpasswordsalt = db.Column(db.String(32), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow)
    friends = db.Column(LONGTEXT, nullable=True)
    is_verified = db.Column(db.Integer, nullable=False, default=1)
    verify = db.relationship('verification_code', backref='account')
    chats = db.Column(LONGTEXT, default='')
    groups = db.Column(LONGTEXT, default='')

    def __repr__(self):
        return '<user %r>' % self.id


class verification_code(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    verification_code = db.Column(db.String(16), nullable=False, default=secrets.token_hex(8))
    valid_until = db.Column(db.DateTime, default=(datetime.utcnow() + timedelta(seconds=300)))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    def __repr__(self):
        return f'Verify({self.verification_code}, Valid-until: {self.valid_until})'


class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    admin = db.Column(LONGTEXT)
    people = db.Column(LONGTEXT, nullable=False)
    unique_key = db.Column(db.String(64), unique=True)


class chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)


    
@app.route('/', methods=["GET"])
def index():
    if current_user.is_authenticated:
        return redirect('/home')
    return render_template('index.html')


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/login', methods=['GET', "POST"])
def login():
    if current_user.is_authenticated:
        return redirect('/home')
    form = forms.LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user:
            password = form.password.data
            password += pepper
            pass_hash = hashlib.sha3_512(password.encode('utf-8')).hexdigest()
            salt = user.usrpasswordsalt
            pass_hash += salt
            pass_hash = hashlib.sha3_512(pass_hash.encode('utf-8')).hexdigest()
            if pass_hash == user.usrpasswordhash:
                login_user(user)
                return redirect('/home')
            else:
                flash('Login Unsuccessful, Please check email and password', 'danger')
        else:
            flash('Login Unsuccessful, Please check email and password', 'danger')
    return render_template('login.html', form=form)


@app.route('/create_account', methods=["GET", "POST"])
def create_account():
    if current_user.is_authenticated:
        return redirect('/home')
    form = forms.RegisterationForm()
    if form.validate_on_submit():
        new_user_usrname = request.form['username']
        new_user_password = request.form['password']
        new_user_email = form.email.data
        salt = secrets.token_hex(16)
        new_user_password += pepper
        user_pass_hash = hashlib.sha3_512(new_user_password.encode('utf-8')).hexdigest()
        user_pass_hash += salt
        user_pass_hash = hashlib.sha3_512(user_pass_hash.encode('utf-8')).hexdigest()
        new_user = Users(usrname=new_user_usrname, usrpasswordhash=user_pass_hash,
                         usrpasswordsalt=salt, email=new_user_email)
        db.session.add(new_user)
        db.session.commit()
        #verification = verification_code(user_id=new_user.id)
        #db.session.add(verification)
        #db.session.commit()
        login_user(new_user)
        #send_verification(new_user.email, verification.verification_code)
        #print(verification.verification_code)
        return redirect('/home')
    else:
        return render_template('create_account.html', form=form)


@app.route('/home')
@login_required
def home():
    return render_template('home.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/')

@app.route('/friends', methods=['GET', 'POST'])
@login_required
def friends():
    if current_user.is_verified == 0:
        return redirect('/home')
    form = forms.SearchFriend()
    valid = form.validate_on_submit()
    adding = False
    friend_ids = current_user.friends
    if friend_ids is not None and friend_ids != '':
        friend_ids_str = friend_ids.split(',')
        friend_ids = []
        for friend_id_str in friend_ids_str:
            friend_ids.append(int(friend_id_str))
        friend_list = []
        for friend_id in friend_ids:
            friend_list.append(Users.query.filter_by(id=friend_id).first())
    else:
        friend_list = []
        friend_ids = []
    if valid:
        adding = True
        users = Users.query.filter(Users.usrname.like('%' + form.name.data + '%')).all()
        return render_template('friends.html', adding=adding, users=users, form=form,
                               friend_ids=friend_ids, friend_list=friend_list)
    return render_template('friends.html', form=form, adding=adding,
                           friend_list=friend_list, friend_ids=friend_ids)


@app.route('/add-friend')
@login_required
def add_friend():
    friend_id = request.args.get('id')
    friend_id = int(friend_id)
    friend = Users.query.filter_by(id=friend_id).first()
    friend_id = str(friend_id)
    if current_user.friends is not None:
        current_friends = current_user.friends.split(',')
        if friend in current_friends:
            return redirect('/friends')
    if current_user.friends is not None and current_user.friends != '':
        current_user.friends += (',' + friend_id)
        if friend.friends is not None and friend.friends != '':
            friend.friends += (',' + str(current_user.id))
        else:
            friend.friends = str(current_user.id)
    else:
        current_user.friends = friend_id
        if friend.friends is not None and friend.friends != '':
            friend.friends += (',' + str(current_user.id))
        else:
            friend.friends = str(current_user.id)
    db.session.commit()
    return redirect('/friends')

@app.route('/del-friend')
@login_required
def del_friend():
    friend_id = str(request.args.get('id'))
    current_friends = current_user.friends.split(',')
    if friend_id in current_friends:
        c_friends = []
        for friend in current_friends:
            c_friends.append(friend)
        c_friends.remove(friend_id)
        c_friends = ','.join(c_friends)
        current_user.friends = c_friends
        user = Users.query.filter_by(id=int(friend_id)).first()
        u_friends = user.friends.split(',')
        u_friends.remove(str(current_user.id))
        u_friends = ','.join(u_friends)
        user.friends = u_friends
        db.session.commit()
        return redirect(url_for('friends'))
    else:
        return "Bad request, either no data was given or there was an error.", 400

@app.route('/chat')
@login_required
def chats():
    friend_id = int(request.args.get('id'))
    user_id = int(current_user.id)
    if friend_id > user_id:
        __cname__ = str(user_id) + '_' + str(friend_id)
    else:
        __cname__ = str(friend_id) + '_' + str(user_id)
    chat_name = chat.query.filter_by(name=__cname__).first()
    print(chat_name)
    if chat_name is not None:
        return redirect('/chat/' + __cname__)
    else:
        new_chat = chat(name=__cname__)
        db.session.add(new_chat)
        db.session.commit()
        return redirect('/chat/' + __cname__)

@app.route('/chat/<name>/dataresponse')
@login_required
def getdata(name):
    if str(current_user.id) not in name.split('_'):
        return 'You have no access to this chat.', 403
    number: int = int(request.args.get('number'))
    res = []
    with open('./chat_data/chat_' + name + '.json', 'r') as fp:
        __cdata__: list = json.load(fp)
    for i in range(number):
        res.append(__cdata__[i])
    res.reverse()
    response = make_response(jsonify(res), 200)
    print(response)
    return response

@app.route('/chat/<name>', methods=['GET', 'POST'])
@login_required
def actual_chat(name):
    people = name.split('_')
    if str(current_user.id) not in people:
        return 'You have no access to this chat.', 403
    __chat__ = chat.query.filter_by(name=name).first
    if __chat__ is not None:
        if os.path.exists('./chat_data/chat_' + name + '.json'):
            with open('./chat_data/chat_' + name + '.json', 'r') as fp:
                __cdata__ = json.load(fp)
                posts = len(__cdata__)
        else:
            with open('./chat_data/chat_' + name + '.json', 'w') as fp:
                fp.write(json.dumps([]))
            with open('./chat_data/chat_' + name + '.json', 'r') as fp:
                __cdata__: list = json.load(fp)
                posts = len(__cdata__)
#    if request.method == 'POST':
#        chat_msg = request.form['chat']
#        __cdata__.insert(0, [chat_msg, current_user.usrname, str(datetime.utcnow())])
#        with open('./chat_data/chat_' + name + '.json', 'w') as fp:
#            fp.write(json.dumps(__cdata__))     depricated
    if request.args:
        counter = int(request.args.get('c'))
        if counter == 0:
            print(f'Returning posts 0 to {quantity}')
            res = make_response(jsonify(__cdata__[0: quantity]), 200)
        elif counter == posts:
            print('no more messages')
            res = make_response(jsonify({}), 200)
        else:
            print(f'returning posts {counter} to {counter + quantity}')
            res = make_response(jsonify(__cdata__[counter: counter + quantity]), 200)
        print(res.data)
        return res
    else:
        _pdata_ = __cdata__  # I forgot why this is here but removing this should be fine
        return render_template('chat.html', name=name)

@socketio.on('chatroominit')
def room_handle(name):
    join_room(name)

@socketio.on('cupdate')
def handle_update(data, name):
    with open('./chat_data/chat_' + name + '.json', 'r') as fp:
        __cdata__: list = json.load(fp)
    __cdata__.insert(0, [data, current_user.usrname, str(datetime.utcnow())])
    with open('./chat_data/chat_' + name + '.json', 'w') as fp:
        fp.write(json.dumps(__cdata__))
    socketio.emit('cupdate', __cdata__[0], to=name)


@app.route('/groups')
@login_required
def group():
    if current_user.is_verified == 0:
        return redirect('/home')
    group_ids = current_user.groups
    if group_ids is not None and group_ids != '':
        group_ids_str = str(group_ids).split(',')
        group_ids = []
        for group_id_str in group_ids_str:
            group_ids.append(int(group_id_str))
        group_list = []
        for group_id in group_ids:
            group_list.append(Group.query.filter_by(id=group_id).first())
    else:
        group_list = []
        group_ids = []
    return render_template('group.html', group_list=group_list, group_ids=group_ids)

@app.route('/CreateGroup', methods=['GET', 'POST'])
@login_required
def create_group():
    form = forms.GroupName()
    if request.method == 'POST':
        gname = str(form.name.data)
        new_group = Group(name=gname, admin=str(current_user.id), people=str(current_user.id))
        db.session.add(new_group)
        db.session.commit()
        if current_user.groups is not None and current_user.groups != '':
            grps = str(current_user.groups).split(',')
            grps.append(new_group.id)
            current_user.groups = ','.join(grps)
            db.session.commit()
        else:
            current_user.groups = str(new_group.id)
            db.session.commit()
        return(redirect('/groups'))
    return render_template('cgroup.html', form=form)


@app.route('/groupchat/<id>', methods=['GET', 'POST'])
@login_required
def groupchat(id):
    usrgrp = str(current_user.groups).split(',')
    if str(id) not in usrgrp:
        return 'You have no access to this group.', 403
    __group__ = Group.query.filter_by(id=id).first()
    if __group__ is not None:
        if os.path.exists('./group_data/group_' + str(id) + '.json'):
            with open('./group_data/group_' + str(id) + '.json', 'r') as fp:
                __gdata__ = json.load(fp)
                posts = len(__gdata__)
        else:
            with open('./group_data/group_' + str(id) + '.json', 'w') as fp:
                fp.write(json.dumps([]))
            with open('./group_data/group_' + str(id) + '.json', 'r') as fp:
                __gdata__: list = json.load(fp)
                posts = len(__gdata__)
    else:
        return '404 not found', 404
    admins = __group__.admin.split(',')
    if str(current_user.id) in admins:
        is_admin = True
    else:
        is_admin = False
#    if request.method == 'POST':
#        group_msg = request.form['group']
#        __gdata__.insert(0, [group_msg, current_user.usrname, str(datetime.utcnow())])
#        with open('./group_data/group_' + str(id) + '.json', 'w') as fp:
#            fp.write(json.dumps(__gdata__))     depricated
    if request.args:
        counter = int(request.args.get('c'))
        if counter == 0:
            print(f'Returning posts 0 to {quantity}')
            res = make_response(jsonify(__gdata__[0: quantity]), 200)
        elif counter == posts:
            print('no more messages')
            res = make_response(jsonify({}), 200)
        else:
            print(f'returning posts {counter} to {counter + quantity}')
            res = make_response(jsonify(__gdata__[counter: counter + quantity]), 200)
        print(res.data)
        return res
    else:
        _pdata_ = __gdata__  # I forgot why this is here but removing this should be fine
        return render_template('groupchat.html', id=id, is_admin=is_admin)

@socketio.on('groupinit')
def room_handle(id):
    join_room(id)

@socketio.on('gupdate')
def handle_update(data, id):
    with open('./group_data/group_' + str(id) + '.json', 'r') as fp:
        __gdata__: list = json.load(fp)
    __gdata__.insert(0, [data, current_user.usrname, str(datetime.utcnow())])
    with open('./group_data/group_' + str(id) + '.json', 'w') as fp:
        fp.write(json.dumps(__gdata__))
    socketio.emit('gupdate', __gdata__[0], to=id)


@app.route('/groupchat/<id>/manage', methods=['GET', 'POST'])
@login_required
def groupinvite(id):
    form = forms.SearchFriend()
    adding = False
    _group_ = Group.query.filter_by(id=id).first()
    people = _group_.people.split(',')
    people_list = []
    for person in people:
        people_list.append(Users.query.filter_by(id=person).first())
    if form.validate_on_submit():
        adding = True
        users = Users.query.filter(Users.usrname.like('%' + form.name.data + '%')).all()
        return render_template('groupinvite.html', form=form, adding=adding, group=_group_, people=people_list, people_id=people, id=id, users=users)
    return render_template('groupinvite.html', form=form, adding=adding, group=_group_, people=people_list, people_id=people, id=id)


@app.route('/groupchat/<id>/add_user', methods=["GET"])
@login_required
def add_user_to_group(id):
    user_id = request.args.get('id')
    user = Users.query.filter_by(id=int(user_id)).first()
    _group_ = Group.query.filter_by(id=int(id)).first()
    if user.groups is not None and user.groups != '':
        user.groups += ','+str(id)
        _group_.people += ','+str(user_id)
    else:
        user.groups = str(id)
        _group_.people += ','+str(user_id)
    db.session.commit()
    return redirect(f'/groupchat/{id}/manage')


@app.route('/groupchat/<id>/remove_user', methods=['GET'])
@login_required
def remove_user(id):
    user_id = request.args.get('id')
    user = Users.query.filter_by(id=int(user_id)).first()
    _group_ = Group.query.filter_by(id=int(id)).first()
    usergroups :list = user.groups.split(',')
    groupusers :list = _group_.people.split(',')
    if str(user_id) in groupusers:
        groupusers.remove(str(user_id))
        print(groupusers)
        _group_.people = ','.join(groupusers)
    if str(id) in usergroups:
        usergroups.remove(str(id))
        user.groups = ','.join(usergroups)
    db.session.commit()
    return redirect(f'/groupchat/{id}/manage')
        

if __name__ == '__main__':
    db.create_all()
    socketio.run(app, host='0.0.0.0', port=443, certfile='C:/Certbot/live/chat.1234567s.tk/fullchain.pem', keyfile='C:/Certbot/live/chat.1234567s.tk/privkey.pem')
