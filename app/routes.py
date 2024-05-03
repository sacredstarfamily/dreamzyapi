from flask import jsonify, abort, render_template, request

from . import app, db
#from data.tasklist import tasks_list
from .models import User, Dream, Interpretation, Exclusivity, Message
from .auth import basic_auth, token_auth
from sqlalchemy import and_
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/users', methods=['POST'])
def create_user():
    if not request.is_json:
        return {'error': 'Your content-type must be application/json'}, 400
    data = request.json
    required_fields = ['firstName', 'lastName', 'username', 'email', 'password']
    missing_fields = []
    for field in required_fields:
        if field not in data:
            missing_fields.append(field)
    if missing_fields:
        return {'error': f"{', '.join(missing_fields)} must be in the request body"}, 400
    first_name = data.get('firstName')
    last_name = data.get('lastName')
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    check_users = db.session.execute(db.select(User).where( (User.username == username) | (User.email == email) )).scalars().all()
    if check_users:
        return {'error': "A user with that username and/or email already exists"}, 400
    new_user = User(first_name=first_name, last_name=last_name,  username=username, email=email, password=password)

    return new_user.to_dict(), 201

@app.route('/token')
@basic_auth.login_required
def get_token():
    user = basic_auth.current_user()
    return user.get_token()

@app.route('/users/me')
@token_auth.login_required
def get_me():
    user = token_auth.current_user()
    return user.to_dict()

@app.route('/users', methods=['PUT'])
@token_auth.login_required
def update_user():
    if not request.is_json:
        return {'error': 'Your content-type must be application/json'}, 400
    data = request.json
    current_user = token_auth.current_user()
    current_user.update(**data)
    return current_user.to_dict()

@app.route('/users', methods=['DELETE'])
@token_auth.login_required
def delete_user():
    current_user = token_auth.current_user()
    current_user.delete()
    return {'success': 'user deleted'}, 204

@app.route('/mydreamz')
@token_auth.login_required
def get_user_dreams():
    current_user = token_auth.current_user()
    dreams = current_user.dreams
    return [dream.to_dict() for dream in dreams]

@app.route('/mydreamz', methods=['POST'])
@token_auth.login_required
def create_dream():
    if not request.is_json:
        return {'error': 'Your content-type must be application/json'}, 400
    data = request.json
    required_fields = ['dream', 'sleepStart', 'sleepEnd', 'exclusivity', 'keywords']
    missing_fields = []
    for field in required_fields:
        if field not in data:
            missing_fields.append(field)
    if missing_fields:
        return {'error': f"{', '.join(missing_fields)} must be in the request body"}, 400
    current_user = token_auth.current_user()
    new_dream = Dream(user_id=current_user.id, dream=data.get('dream'), sleep_start=data.get('sleepStart'), sleep_end=data.get('sleepEnd'), exclusivity=data.get('exclusivity'), keywords=data.get('keywords'))
    return new_dream.to_dict(), 201

@app.route('/mydreamz/<int:dream_id>', methods=['PUT'])
@token_auth.login_required
def update_dream(dream_id):
    if not request.is_json:
        return {'error': 'Your content-type must be application/json'}, 400
    data = request.json
    current_user = token_auth.current_user()
    dream = db.session.execute(db.select(Dream).where(Dream.id == dream_id)).scalar_one_or_none()
    if dream is None:
        return {'error': 'Dream not found'}, 404
    if dream.user_id != current_user.id:
        return {'error': 'You are not authorized to update this dream'}, 403
    dream.update(**data)
    return dream.to_dict()

@app.route('/mydreamz/<int:dream_id>', methods=['DELETE'])
@token_auth.login_required
def delete_dream(dream_id):
    current_user = token_auth.current_user()
    dream = db.session.execute(db.select(Dream).where(Dream.id == dream_id)).scalar_one_or_none()
    if dream is None:
        return {'error': 'Dream not found'}, 404
    if dream.user_id != current_user.id:
        return {'error': 'You are not authorized to delete this dream'}, 403
    dream.delete()
    return {'success': 'dream deleted'}, 204

@app.route('/getdreamz')
@token_auth.login_required
def get_dreams():
    select_stmt = db.select(Dream).where(Dream.exclusivity == Exclusivity.PUBLIC)
    search = request.args.get('search')
    if search:
        select_stmt = select_stmt.where(and_(Dream.keywords.ANY(f'%{search}%'), Dream.exclusivity == Exclusivity.PUBLIC))
    dreams = db.session.execute(select_stmt).scalars().all()
    return [dream.to_dict() for dream in dreams]

@app.route('/interpretations', methods=['POST'])
@token_auth.login_required
def create_interpretation():
    if not request.is_json:
        return {'error': 'Your content-type must be application/json'}, 400
    data = request.json
    required_fields = ['interpretation', 'dreamId']
    missing_fields = []
    for field in required_fields:
        if field not in data:
            missing_fields.append(field)
    if missing_fields:
        return {'error': f"{', '.join(missing_fields)} must be in the request body"}, 400
    current_user = token_auth.current_user()
    dream = db.session.execute(db.select(Dream).where(Dream.id == data.get('dreamId'))).scalar_one_or_none()
    if dream is None:
        return {'error': 'Dream not found'}, 404
    new_interpretation = Interpretation(interpretation=data.get('interpretation'), dream_id=dream.id, interpreter_id=current_user.id)
    return new_interpretation.to_dict(), 201

@app.route('/interpretations/<int:interpretation_id>', methods=['PUT'])
@token_auth.login_required
def update_interpretation(interpretation_id):
    if not request.is_json:
        return {'error': 'Your content-type must be application/json'}, 400
    data = request.json
    current_user = token_auth.current_user()
    interpretation = db.session.execute(db.select(Interpretation).where(Interpretation.id == interpretation_id)).scalar_one_or_none()
    if interpretation is None:
        return {'error': 'Interpretation not found'}, 404
    if interpretation.interpreter_id != current_user.id:
        return {'error': 'You are not authorized to update this interpretation'}, 403
    interpretation.update(**data)
    return interpretation.to_dict()

@app.route('/users/<int:user_id>/messages')
@token_auth.login_required
def getMessages(user_id):
    current_user = token_auth.current_user()
    user = db.session.execute(db.select(User).where(User.id == user_id)).scalar_one_or_none()
    if user is None:
        return {'error': 'User not found'}, 404
    if current_user.id == user.id:
        return {'error': 'You cannot send messages to yourself'}, 403
    messages = db.session.execute(db.select(Message).where(Message.sender_id == current_user.id, Message.receiver_id == user.id)).scalars().all()
    return {'message': [message.to_dict() for message in messages]}



