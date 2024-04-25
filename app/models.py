import secrets
from . import db
from datetime import datetime, timezone, timedelta

from sqlalchemy.dialects.postgresql import ARRAY

from werkzeug.security import generate_password_hash, check_password_hash
import enum
from sqlalchemy import ARRAY, Enum, String
class Exclusivity(enum.Enum):
    PUBLIC = 0
    EXCLUSIVE = 1
    PRIVATE = 2
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String, nullable=False)
    last_name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, index=True, unique=True)
    username = db.Column(db.String, index=True, unique=True)
    password = db.Column(db.String(528))
    location = db.Column(db.String(64), nullable=True)
    token = db.Column(db.String(32), index=True, unique=True)
    token_expiration = db.Column(db.DateTime)
    dreams = db.relationship('Dream', back_populates='author', cascade='all,delete')
    interpretations = db.relationship('Interpretation', back_populates='interpreter', cascade='all,delete')
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__set_password(kwargs.get('password', ''))
        
    def __repr__(self):
        return f"<User {self.username}>"

    def __set_password(self, plaintext_password):
        self.password_hash = generate_password_hash(plaintext_password)
        self.save()
        
    def check_password(self, plaintext_password):
        return check_password_hash(self.password_hash, plaintext_password)
    
    def save(self):
        db.session.add(self)
        db.session.commit()

    def update(self, **kwargs):
        allowed_fields = {'username', 'first_name', 'last_name', 'email', 'password', 'location'}
        for attr, value in kwargs.items():
            if attr in allowed_fields:
                setattr(self, attr, value)
        self.save()
        
    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def get_token(self):
        now = datetime.now(timezone.utc)
        if self.token and self.token_expiration > now + timedelta(seconds=60):
            return self.token
        self.token = secrets.token_hex(16)
        self.token_expiration = now + timedelta(seconds=3600)
        db.session.commit()
        return self.token

    def revoke_token(self):
        self.token_expiration = datetime.now(timezone.utc) - timedelta(seconds=1)

    @staticmethod
    def check_token(token):
        user = User.query.filter_by(token=token).first()
        if user is None or user.token_expiration < datetime.now(timezone.utc):
            return None
        return user
    
    def to_dict(self):
        data = {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'username': self.username
        }
        return data
    
class Dream(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dream = db.Column(db.String(6000))
    exclusivity = db.Column(Enum(Exclusivity), default=Exclusivity.PRIVATE)
    sleep_start = db.Column(db.String)
    sleep_end = db.Column(db.String)
    keywords = db.Column(ARRAY(db.String), index=True)
    log_date = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    author = db.relationship('User', back_populates='dreams')
    interpretations = db.relationship('Interpretation', back_populates='dream', cascade='all,delete')
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.save()
        
    def __repr__(self):
        return '<Dream {}>'.format(self.dream)
    
    def save(self):
        db.session.add(self)
        db.session.commit()
    
    def delete(self):
        db.session.delete(self)
        db.session.commit()
        
    def to_dict(self):
        data = {
            'id': self.id,
            'dream': self.dream,
            'isPublic': self.exclusivity,
            'dream_date': self.dream_date,
            'user_id': self.user_id
        }
        return data

class Interpretation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    interpretation = db.Column(db.String(6000))
    log_date = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    dream_id = db.Column(db.Integer, db.ForeignKey('dream.id'))
    exclusivity = db.Column(Enum(Exclusivity), default=Exclusivity.PUBLIC)
    dream = db.relationship('Dream', back_populates='interpretations')
    interpreter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    interpreter = db.relationship('User')
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.save()
        
    def __repr__(self):
        return '<Interpretation {}>'.format(self.interpretation)
    
    def save(self):
        db.session.add(self)
        db.session.commit()
    
    def delete(self):
        db.session.delete(self)
        db.session.commit()
        
    def to_dict(self):
        data = {
            'id': self.id,
            'interpretation': self.interpretation,
            'log_date': self.log_date,
            'dream_id': self.dream_id,
            'interpreter_id': self.interpreter_id
        }
        return data