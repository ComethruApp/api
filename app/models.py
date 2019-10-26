from app import app, db, bcrypt
import datetime
import jwt
import hashlib


followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('followed_id', db.Integer, db.ForeignKey('users.id'))
)

hostships = db.Table('hostships',
    db.Column('host_id', db.Integer, db.ForeignKey('users.id')),
    db.Column('event_id', db.Integer, db.ForeignKey('events.id'))
)

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(64))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    verified = db.Column(db.Boolean, nullable=False, default=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    bio = db.Column(db.String(127))
    # primaryjoin indicates the condition that links the left side entity (the follower user) with the association table. The join condition for the left side of the relationship is the user ID matching the follower_id field of the association table. The followers.c.follower_id expression references the follower_id column of the association table.
    # secondaryjoin indicates the condition that links the right side entity (the followed user) with the association table. This condition is similar to the one for primaryjoin, with the only difference that now I'm using followed_id, which is the other foreign key in the association table.
    # see more: https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-viii-followers
    followed = db.relationship(
            'User', secondary=followers,
            primaryjoin=(followers.c.follower_id == id),
            secondaryjoin=(followers.c.followed_id == id),
            backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')
    hosted = db.relationship(
            'Event', secondary=hostships,
            primaryjoin=(hostships.c.host_id == id),
            secondaryjoin=(hostships.c.event_id == id),
            backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'))

    def __init__(self, name, email, password, verified=False, admin=False, bio=''):
        self.name = name
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.registered_on = datetime.datetime.now()
        self.verified = verified
        self.admin = admin
        self.bio = bio

    def encode_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365, seconds=0),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            app.config.get('SECRET_KEY'),
            algorithm='HS256'
        ), payload['exp']

    def avatar(self):
        return hashlib.md5(self.email.encode('utf-8')).hexdigest()

    @staticmethod
    def decode_token(token):
        """
        Validates the auth token
        :param token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(token, app.config.get('SECRET_KEY'))
            is_blacklisted_token = BlacklistedToken.check_blacklist(token)
            if is_blacklisted_token:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'

    def json(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'verified': self.verified,
            'avatar': self.avatar(),
            'bio': self.bio,
        }

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)

    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0

class BlacklistedToken(db.Model):
    """
    Token Model for storing JWT tokens
    """
    __tablename__ = 'blacklisted_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.now()

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistedToken.query.filter_by(token=str(auth_token)).first()
        return bool(res)


class Event(db.Model):
    """
    Does it need that much explanation?
    """
    __tablename__ = 'events'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(64))
    registered_on = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(1024))

    location_name = db.Column(db.String(127))
    location_lat = db.Column(db.Float)
    location_lon = db.Column(db.Float)

    time_start = db.Column(db.DateTime, nullable=False)
    time_end = db.Column(db.DateTime)

    venmo = db.Column(db.String(32))


    hosts = db.relationship(
        'User', secondary=hostships,
        primaryjoin=(hostships.c.event_id == id),
        secondaryjoin=(hostships.c.host_id == id),
        backref=db.backref('hostships', lazy='dynamic'), lazy='dynamic')

class School(db.Model):
    __tablename__ = 'schools'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(64), unique=True)
    nickname = db.Column(db.String(16), unique=True)
    color = db.Column(db.String(6), nullable=True)

    students = db.relationship('User', backref='bot', lazy='dynamic')
