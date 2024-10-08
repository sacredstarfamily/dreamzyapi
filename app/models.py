import secrets

from flask import jsonify
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
    reviews = db.relationship('Review', back_populates='user', cascade='all,delete-orphan')
    username = db.Column(db.String, index=True, unique=True)
    password = db.Column(db.String(528))
    location = db.Column(db.String(64), nullable=True)
    token = db.Column(db.String, index=True, unique=True)
    token_expiration = db.Column(db.DateTime(timezone=True))
    dreams = db.relationship('Dream', back_populates='author', cascade='all,delete')
    interpretations = db.relationship('Interpretation', back_populates='interpreter', cascade='all,delete')
    liked_dreams = db.Column(ARRAY(db.Integer), default=[])
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.__set_password(kwargs.get('password', ''))
        
    def __repr__(self):
        return f"<User {self.username}>"

    def __set_password(self, plaintext_password):
        self.password = generate_password_hash(plaintext_password)
        self.save()
        
    def check_password(self, plaintext_password):
        return check_password_hash(self.password, plaintext_password)
    
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
        if self.token and self.token_expiration > now + timedelta(minutes=1):
            return {"token": self.token, "tokenExpiration": self.token_expiration}
        self.token = secrets.token_hex(16)
        self.token_expiration = now + timedelta(hours=1)
        self.save()
        return {"token": self.token, "tokenExpiration": self.token_expiration}

    def revoke_token(self):
        self.token_expiration = datetime.now(timezone.utc) - timedelta(seconds=1)

    @staticmethod
    def check_token(token):
        user = User.query.filter_by(token=token).first()
        if user is None or user.token_expiration < datetime.now(timezone.utc):
            return None
        return user
    
    def to_dict(self):
        return {
            'id': self.id,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'email': self.email,
            'username': self.username,
        }
    
class Dream(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dream = db.Column(db.String(6000))
    exclusivity = db.Column(Enum(Exclusivity), default=Exclusivity.PRIVATE)
    sleep_start = db.Column(db.String)
    sleep_end = db.Column(db.String)
    keywords = db.Column(ARRAY(db.String), index=True)
    log_date = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    likes = db.Column(db.Integer, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    interpretations = db.relationship('Interpretation', back_populates='dream', cascade='all,delete')
    author = db.relationship('User', back_populates='dreams')
    who_liked = db.Column(ARRAY(db.String), default=[])
    reviews = db.relationship('Review', back_populates='dream', cascade='all,delete-orphan')
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.save()
        
    def __repr__(self):
        return f'<Dream {self.dream}>'
    
    def save(self):
        db.session.add(self)
        db.session.commit()
        
    def update(self, **kwargs):
        allowed_fields = {'dream', 'exclusivity', 'sleep_start', 'sleep_end', 'keywords', 'allowed_user','who_liked','likes'}
        for attr, value in kwargs.items():
            if attr in allowed_fields:
                setattr(self, attr, value)
        self.save()
        
    def delete(self):
        db.session.delete(self)
        db.session.commit()
        
    def to_dict(self):
        return {
            'id': self.id,
            'dream': self.dream,
            'isPublic': self.exclusivity.name,
            'dream_date': self.log_date,
            'sleepStart': self.sleep_start,
            'sleepEnd': self.sleep_end,
            'user_id': self.user_id,
            'keywords': list(self.keywords),
            'author': self.author.to_dict(),
            'likes': self.likes,
            'who_liked': self.who_liked,
            'interpretations': [
                interpretation.to_dict() for interpretation in self.interpretations
            ],
        }

class Interpretation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    interpretation = db.Column(db.String(6000))
    log_date = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    dream_id = db.Column(db.Integer, db.ForeignKey('dream.id'))
    exclusivity = db.Column(Enum(Exclusivity), default=Exclusivity.PUBLIC)
    dream = db.relationship('Dream', back_populates='interpretations')
    interpreter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    interpreter = db.relationship('User', back_populates='interpretations')
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.save()
        
    def __repr__(self):
        return f'<Interpretation {self.interpretation}>'
    
    def save(self):
        db.session.add(self)
        db.session.commit()
    
    def delete(self):
        db.session.delete(self)
        db.session.commit()
        
    def to_dict(self):
        return {
            'id': self.id,
            'interpretation': self.interpretation,
            'log_date': self.log_date,
            'dream_id': self.dream_id,
            'interpreter_id': self.interpreter_id,
        }
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(6000))
    log_date = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.save()
        
    def __repr__(self):
        return f'<Message {self.message}>'
    
    def save(self):
        db.session.add(self)
        db.session.commit()
    
    def delete(self):
        db.session.delete(self)
        db.session.commit()
    def getSender(self):
        return db.session.execute(db.select(User).where(User.id == self.sender_id)).scalar_one_or_none()
       
    def to_dict(self):
        sender = self.getSender()
        return {
            'id': self.id,
            'message': self.message,
            'log_date': self.log_date,
            'sender_id': self.sender_id,
            'sender': sender.to_dict(),
            'receiver_id': self.receiver_id,
        }
        
class Friends(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', foreign_keys=[user_id])
    friend = db.relationship('User', foreign_keys=[friend_id])
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.save()
        
    def __repr__(self):
        return f'<Friendship {self.user_id} - {self.friend_id}>'
    
    def save(self):
        db.session.add(self)
        db.session.commit()
    
    def delete(self):
        db.session.delete(self)
        db.session.commit()
    def getFriend(self):
        return db.session.execute(db.select(User).where(User.id == self.friend_id)).scalar_one_or_none()

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'friend_id': self.friend_id,
        }


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    log_date = db.Column(db.DateTime, index=True, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    dream_id = db.Column(db.Integer, db.ForeignKey('dream.id'))
    user = db.relationship('User', back_populates='reviews')
    dream = db.relationship('Dream', back_populates='reviews')

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.save()

    def __repr__(self):
        return f'<Review {self.id}>'

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def to_dict(self):
        return {
            'id': self.id,
            'content': self.content,
            'rating': self.rating,
            'log_date': self.log_date.isoformat(),
            'user_id': self.user_id,
            'dream_id': self.dream_id
        }

