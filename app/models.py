from app import app, db, bcrypt
import datetime
import jwt
import hashlib
import dateutil.parser
import random

EVENT_LENGTH = datetime.timedelta(hours=10)

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
    db.Column('followed_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
)

hostships = db.Table('hostships',
    db.Column('user_id',  db.Integer, db.ForeignKey('users.id'),  nullable=False),
    db.Column('event_id', db.Integer, db.ForeignKey('events.id'), nullable=False),
)

friendships = db.Table('friendships',
    db.Column('friender_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
    db.Column('friended_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
)

friend_requests = db.Table('friend_requests',
    db.Column('friender_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
    db.Column('friended_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
)

invitations = db.Table('invitations',
    db.Column('event_id', db.Integer, db.ForeignKey('events.id'), nullable=False),
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
)

blocks = db.Table('blocks',
    db.Column('blocker_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
    db.Column('blocked_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
)

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    verified = db.Column(db.Boolean, nullable=False, default=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    lat = db.Column(db.Float, nullable=True)
    lng = db.Column(db.Float, nullable=True)
    current_event_id = db.Column(db.Integer, db.ForeignKey('events.id'))

    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'))

    followed = db.relationship(
            'User', secondary=followers,
            primaryjoin=(followers.c.follower_id == id),
            secondaryjoin=(followers.c.followed_id == id),
            backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')

    hosted = db.relationship(
            'Event', secondary=hostships, passive_deletes=True,
            backref=db.backref('hostships', lazy='subquery'), lazy=True)

    friended = db.relationship(
            'User', secondary=friendships,
            primaryjoin=(friendships.c.friender_id == id),
            secondaryjoin=(friendships.c.friended_id == id),
            backref=db.backref('frienders', lazy='dynamic'), lazy='dynamic')

    friend_requests_sent = db.relationship(
            'User', secondary=friend_requests,
            primaryjoin=(friend_requests.c.friender_id == id),
            secondaryjoin=(friend_requests.c.friended_id == id),
            backref=db.backref('friend_requests_received', lazy='dynamic'), lazy='dynamic')

    blocked = db.relationship(
            'User', secondary=blocks,
            primaryjoin=(blocks.c.blocker_id == id),
            secondaryjoin=(blocks.c.blocked_id == id),
            backref=db.backref('blocked_by', lazy='dynamic'), lazy='dynamic')

    def __init__(self, name, email, password, school_id, confirmed=False):
        self.name = name
        self.email = email
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()
        self.school_id = school_id
        self.confirmed = confirmed
        self.registered_on = datetime.datetime.now()

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

    def json(self, me):
        """
        Generate JSON representation of this user.

        :param me: User currently logged in. Necessary to generate boolean fields describing relationships.
        """
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'verified': self.verified,
            'avatar': self.avatar(),
            # Is this user me?
            'is_me': (self == me),
            # Did this user request/send a friend request from/to this user?
            'has_sent_friend_request': self.has_sent_friend_request(me),
            'has_received_friend_request': self.has_received_friend_request(me),
            # Is the current user friends with this user?
            'is_friend': self.is_friends_with(me),
        }

    def follow(self, user):
        if not self.is_following(user):
            self.followed.append(user)
            return True
        return False

    def unfollow(self, user):
        if self.is_following(user):
            self.followed.remove(user)
            return True
        return False

    def is_following(self, user):
        return self.followed.filter(followers.c.followed_id == user.id).count() > 0

    def block(self, user):
        if not self.has_blocked(user):
            self.blocked.append(user)
            return True
        return False

    def unblock(self, user):
        if self.has_blocked(user):
            self.blocked.remove(user)
            return True
        return False

    def has_blocked(self, user):
        return self.blocked.filter(blocks.c.blocked_id == user.id).count() > 0

    def friends(self):
        """
        Get a list of people you have friended and who have friended you whose friendships are confirmed.
        """
        return self.friended.all() + self.frienders.all()

    def friend_requests(self):
        """
        Get a list of users who have sent friend requests to you that are not confirmed yet.
        """
        return self.friend_requests_received.all()

    def friend_request(self, user):
        if self.has_friend_request(user) or self.is_friends_with(user):
            return False
        self.friend_requests_sent.append(user)
        return True

    def has_received_friend_request(self, user) -> bool:
        return self.friend_requests_received.filter(friend_requests.c.friender_id == user.id).count() > 0

    def has_sent_friend_request(self, user) -> bool:
        return self.friend_requests_sent.filter(friend_requests.c.friended_id == user.id).count() > 0

    def has_friend_request(self, user) -> bool:
        """
        Return whether there is an active friend request (received or sent) to the given user.
        """
        return self.has_received_friend_request(user) or self.has_sent_friend_request(user)

    def is_friends_with(self, user) -> bool:
        return self.friended.filter(friendships.c.friended_id == user.id).count() > 0 \
            or self.frienders.filter(friendships.c.friender_id == user.id).count() > 0

    def friends_at_event(self, event_id):
        return self.friended.filter(User.current_event_id == event_id).all() \
             + self.frienders.filter(User.current_event_id == event_id).all()

    @staticmethod
    def from_token(token):
        user_id = User.decode_token(token)
        user = User.query.get(user_id)
        return user


class BlacklistedToken(db.Model):
    __tablename__ = 'blacklisted_tokens'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    token = db.Column(db.String(500), unique=True, nullable=False)
    blacklisted_on = db.Column(db.DateTime, nullable=False)

    def __init__(self, token):
        self.token = token
        self.blacklisted_on = datetime.datetime.utcnow()

    @staticmethod
    def check_blacklist(auth_token):
        # check whether auth token has been blacklisted
        res = BlacklistedToken.query.filter_by(token=str(auth_token)).first()
        return bool(res)


class Event(db.Model):
    __tablename__ = 'events'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(64), nullable=False)
    registered_on = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(1024))

    location = db.Column(db.String(127), nullable=False)
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)

    open = db.Column(db.Boolean, default=True)
    transitive_invites = db.Column(db.Boolean, default=False)
    capacity = db.Column(db.Integer)

    time = db.Column(db.DateTime, nullable=False)

    hosts = db.relationship(
        'User', secondary=hostships,
        backref=db.backref('hostships', lazy='dynamic', cascade="all, delete"), lazy='dynamic')

    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'))

    invitees = db.relationship(
            'User', secondary=invitations,
            backref=db.backref('invited_to', lazy='dynamic'), lazy='dynamic')

    # People currently at event
    # TODO: this name implies a list of all people that have attended. Maybe differentiate between the two?
    #attendees = db.relationship('User', backref='current_event', lazy='dynamic')

    def __init__(self, raw, school_id):
        self.time = dateutil.parser.parse(raw.pop('time', None))
        for field in raw:
            setattr(self, field, raw[field])
        self.registered_on = datetime.datetime.utcnow()
        self.school_id = school_id

    def add_host(self, user):
        self.hosts.append(user)

    def hosted_by(self, user):
        return self.hosts.filter(hostships.c.user_id == user.id).count() > 0

    def invite(self, user):
        if self.is_invited(user):
            return False
        self.invitees.append(user)
        return True

    def is_invited(self, user) -> bool:
        """
        Return whether there is an invitation to this event for the given user.
        """
        return self.invitees.filter(invitations.c.user_id == user.id).count() > 0

    # TODO: feels like this should be a method of user?
    @staticmethod
    def get_feed(school_id):
        now = datetime.datetime.utcnow()
        return Event.query.filter(
            # TODO: also get private events in one query
            Event.open == True,
            Event.school_id == school_id,
            Event.time < now,
            now - EVENT_LENGTH < Event.time,
        ).all()

    def json(self, me):
        raw = {key: getattr(self, key) for key in ('id', 'name', 'description',
                                                   'location', 'lat', 'lng',
                                                   'time', 'open', 'transitive_invites', 'capacity')}
        raw.update({
            # TODO: don't get time every repetition
            'happening_now': self.time < datetime.datetime.utcnow() < self.time + EVENT_LENGTH,
            'mine': self.hosted_by(me),
            'invited_me': self.is_invited(me),
            'people': User.query.filter(User.current_event_id == self.id).count(),
            'rating': random.randint(0, 50) / 10,
            'hosts': [host.json(me) for host in self.hosts],
        })
        return raw


class School(db.Model):
    __tablename__ = 'schools'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(64), unique=True)
    nickname = db.Column(db.String(16), unique=True)
    color = db.Column(db.String(6), nullable=True)
    domain = db.Column(db.String(32), unique=True)

    students = db.relationship('User', backref='users', lazy='dynamic')
    events = db.relationship('Event', backref='events', lazy='dynamic')

    @staticmethod
    def get_by_email(email):
        domain = email.split('@')[-1]
        return School.query.filter_by(domain=domain).first()
