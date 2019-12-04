from app import app, db, bcrypt
from sqlalchemy import desc
import datetime
import jwt
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
    registered_on = db.Column(db.DateTime, nullable=False)

    # User information
    name = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    avatar = db.Column(db.String(120), nullable=True, default='')
    confirmed = db.Column(db.Boolean, default=False)
    verified = db.Column(db.Boolean, nullable=False, default=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    # Columns related to current position
    lat = db.Column(db.Float, nullable=True)
    lng = db.Column(db.Float, nullable=True)
    current_event_id = db.Column(db.Integer, db.ForeignKey('events.id'))

    # Relationships
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'))
    followed = db.relationship(
            'User', secondary=followers,
            primaryjoin=(followers.c.follower_id == id),
            secondaryjoin=(followers.c.followed_id == id),
            backref=db.backref('followers', lazy='dynamic'), lazy='dynamic')
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
    votes = db.relationship('Vote', backref='event', lazy=True)

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

    def events_hosted(self):
        # TODO: the only reason "events_" is in the name of this function is because "hosted" conflicts with the
        # backref name that it uses... find a way to be cleaner about that.
        return self.hosted.order_by(desc(Event.time)).all()

    def search(self, query: str):
        users = User.query.filter(User.school_id == self.school_id,
                                  User.id != self.id,
                                  User.name.ilike('%' + query + '%'))
        return users.all()

    @staticmethod
    def decode_token(token):
        """
        Validates the auth token
        :param token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(token, app.config.get('SECRET_KEY'))
            is_blacklisted = BlacklistedToken.check_blacklist(token)
            if is_blacklisted:
                return 'Token blacklisted. Please log in again.'
            else:
                return payload['sub']
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'

    @staticmethod
    def from_token(token):
        user_id = User.decode_token(token)
        user = User.query.get(user_id)
        return user


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
        if not self.is_blocking(user):
            self.blocked.append(user)
            return True
        return False

    def unblock(self, user):
        if self.is_blocking(user):
            self.blocked.remove(user)
            return True
        return False

    def is_blocking(self, user):
        return self.blocked.filter(blocks.c.blocked_id == user.id).count() > 0


    def friends(self):
        """
        Get a list of people you have friended and who have friended you whose friendships are confirmed.
        """
        return self.friended.all() + self.frienders.all()

    def is_friends_with(self, user) -> bool:
        return self.friended.filter(friendships.c.friended_id == user.id).count() > 0 \
            or self.frienders.filter(friendships.c.friender_id == user.id).count() > 0

    def friends_at_event(self, event_id):
        return self.friended.filter(User.current_event_id == event_id).all() \
             + self.frienders.filter(User.current_event_id == event_id).all()


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

    def feed(self):
        my_closed_events = self.hosted.filter(
            Event.open == False,
        )
        invited_closed_events = self.invited_to.filter(
            Event.open == False,
        )
        closed_events = my_closed_events.union(invited_closed_events)
        open_events = Event.query.filter(
            Event.open == True,
            Event.school_id == self.school_id,
        )
        events = closed_events.union(open_events)
        # Filter out events that are over
        now = datetime.datetime.utcnow()
        events = events.filter(
            Event.time < now,
            Event.ended == False,
            now - EVENT_LENGTH < Event.time,
            (Event.end_time == None) | (now < Event.end_time),
        )
        # Put private events first
        events = events.order_by(Event.open)
        return events.all()

    def vote_on(self, user):
        if not self.is_blocking(user):
            self.blocked.append(user)
            return True
        return False

    def unvote_on(self, user):
        if self.is_blocking(user):
            self.blocked.remove(user)
            return True
        return False

    def is_blocking(self, user):
        return self.blocked.filter(blocks.c.blocked_id == user.id).count() > 0


    def json(self, me, event=None):
        """
        Generate JSON representation of this user.

        :param me: User currently logged in. Necessary to generate boolean fields describing relationships.
        :param event: optionally specify an event to check invitation status for.
        """
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'verified': self.verified,
            'avatar': self.avatar,
            # Is this user me?
            'is_me': (self == me),
            # Did this user request/send a friend request from/to this user?
            'has_sent_friend_request': self.has_sent_friend_request(me),
            'has_received_friend_request': self.has_received_friend_request(me),
            # Is the current user friends with this user?
            'is_friend': self.is_friends_with(me),
            'invited': event.is_invited(self) if event else None,
        }


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
    registered_on = db.Column(db.DateTime, nullable=False)

    # Metadata
    name = db.Column(db.String(64), nullable=False)
    description = db.Column(db.String(1024))

    location = db.Column(db.String(127), nullable=False)
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)

    open = db.Column(db.Boolean, default=True)
    transitive_invites = db.Column(db.Boolean, default=False)
    capacity = db.Column(db.Integer)

    time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    ended = db.Column(db.Boolean, default=False)

    # Relationships
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'))
    hosts = db.relationship(
        'User', secondary=hostships,
        backref=db.backref('hosted', lazy='dynamic', cascade="all, delete"), lazy='dynamic'
    )
    invitees = db.relationship(
        'User', secondary=invitations,
        backref=db.backref('invited_to', lazy='dynamic'), lazy='dynamic'
    )
    votes = db.relationship('Vote', backref='event', lazy=True)

    def __init__(self, raw, school_id):
        self.time = datetime.datetime.fromisoformat(raw.pop('time'))
        self.time = self.time.astimezone(datetime.timezone.utc)
        raw_end_time = raw.pop('end_time', None)
        if raw_end_time:
            self.end_time = datetime.datetime.fromisoformat(raw_end_time)
            self.end_time = self.end_time.astimezone(datetime.timezone.utc)
        for field in raw:
            setattr(self, field, raw[field])
        self.registered_on = datetime.datetime.utcnow()
        self.school_id = school_id

    def add_host(self, user):
        self.hosts.append(user)

    def is_hosted_by(self, user) -> bool:
        return self.hosts.filter(hostships.c.user_id == user.id).count() > 0

    def invite(self, user) -> bool:
        """
        Send an invite to a given user if they aren't already invited.
        :param user: User to invite.
        :return: whether user was was invited, i.e. if they weren't already invited.
        """
        if self.is_invited(user):
            return False
        self.invitees.append(user)
        return True

    def is_invited(self, user) -> bool:
        """
        Return whether there is an invitation to this event for the given user.
        """
        return self.invitees.filter(invitations.c.user_id == user.id).count() > 0

    def happening_now(self):
        # TODO: don't get time every repetition
        now = datetime.datetime.utcnow()
        has_started = (self.time < now)
        has_not_been_ended = (not self.ended)
        is_not_over = (now < (self.end_time or (self.time + EVENT_LENGTH)))
        return (has_started and is_not_over and has_not_been_ended)

    def people(self):
        return User.query.filter(User.current_event_id == self.id).count()

    def get_vote(self, user):
        return Vote.query.filter(Vote.event_id == self.id,
                                 Vote.user_id == user.id).first()

    def json(self, me):
        raw = {key: getattr(self, key) for key in ('id', 'name', 'description',
                                                   'location', 'lat', 'lng',
                                                   'time', 'end_time', 'open',
                                                   'transitive_invites', 'capacity')}
        vote = self.get_vote(me)
        raw.update({
            'happening_now': self.happening_now(),
            'mine': self.is_hosted_by(me),
            'invited_me': self.is_invited(me),
            'people': self.people(),
            'vote': vote.positive if vote else None,
            'review': vote.review if vote else None,
            'rating': random.randint(0, 50) / 10,
            'hosts': [host.json(me) for host in self.hosts],
        })
        return raw


class Vote(db.Model):
    __tablename__ = 'votes'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    positive = db.Column(db.Boolean)
    review = db.Column(db.String(1024))

    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)

    def __init__(self, user, event, positive, text):
        self.user_id = user.id
        self.event_id = event.id
        self.positive = positive
        self.text = text


class School(db.Model):
    __tablename__ = 'schools'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    name = db.Column(db.String(64), unique=True)
    nickname = db.Column(db.String(16), unique=True)
    domain = db.Column(db.String(32), unique=True)
    color = db.Column(db.String(6), nullable=True)

    # Relationships
    students = db.relationship('User', backref='users', lazy='dynamic')
    events = db.relationship('Event', backref='events', lazy='dynamic')

    @staticmethod
    def from_email(email):
        """
        Given a raw email, extract the domain and find a School with that domain.
        :param email: email to get school for.
        :return: School with that email domain, or None if no school uses that domain.
        """
        domain = email.split('@')[-1]
        return School.query.filter_by(domain=domain).first()
