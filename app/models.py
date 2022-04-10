from app import app, db, bcrypt
from app.facebook import facebook
from sqlalchemy import desc
import datetime
import jwt
import random

UPCOMING_RANGE = datetime.timedelta(days=5)
EVENT_LENGTH = datetime.timedelta(hours=10)
AFTER_END_VISIBILITY = datetime.timedelta(hours=20)

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
    db.Column('followed_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
)

hostships = db.Table('hostships',
    db.Column('user_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
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

taggings = db.Table('taggings',
    db.Column('event_id', db.Integer, db.ForeignKey('events.id'), nullable=False),
    db.Column('tag_name', db.String, db.ForeignKey('tags.name'), nullable=False),
)

blocks = db.Table('blocks',
    db.Column('blocker_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
    db.Column('blocked_id', db.Integer, db.ForeignKey('users.id'), nullable=False),
)


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    registered_on = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=True)

    # User information
    name = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    year = db.Column(db.Integer, nullable=True)
    password = db.Column(db.String(255), nullable=False)
    confirmed = db.Column(db.Boolean, default=False)
    verified = db.Column(db.Boolean, nullable=False, default=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)

    # Facebook integration
    # facebook_id is None if no account has been connected
    facebook_id = db.Column(db.String(100), nullable=True)
    facebook_name = db.Column(db.String(50), nullable=True)

    # Things related to location
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
    invited_to = db.relationship('Event', secondary='invitations', backref=db.backref('users', lazy='dynamic'), lazy='dynamic')
    updates = db.relationship('Update', backref='user', lazy=True)
    reviews = db.relationship('Review', backref='user', lazy=True)

    def __init__(self, name, email, password, school_id, confirmed=False, year=None):
        self.name = name
        self.email = email
        self.set_password(password)
        self.school_id = school_id
        self.confirmed = confirmed
        self.year = year
        self.registered_on = datetime.datetime.utcnow()

    def generate_token(self):
        """
        Generate auth token.
        :return: token and expiration timestamp.
        """
        now = datetime.datetime.utcnow()
        payload = {
            'iat': now,
            'exp': now + datetime.timedelta(days=3650),
            'sub': self.id,
        }
        return jwt.encode(
            payload,
            app.config.get('SECRET_KEY'),
            algorithm='HS256'
        ), payload['exp']

    @staticmethod
    def from_token(token):
        """
        Decode/validate an auth token.
        :param token: token to decode.
        :return: User whose token this is, or None if token invalid/no user associated
        """
        try:
            payload = jwt.decode(token, app.config.get('SECRET_KEY'), algorithms=['HS256'])
            is_blacklisted = BlacklistedToken.check_blacklist(token)
            if is_blacklisted:
                # Token was blacklisted following logout
                return None
            return User.query.get(payload['sub'])
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            # Signature expired, or token otherwise invalid
            return None

    def is_password_correct(self, password: str) -> bool:
        return bcrypt.check_password_hash(self.password, password)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(
            password, app.config.get('BCRYPT_LOG_ROUNDS')
        ).decode()

    def events_hosted(self, include_past=False):
        """
        Get events this user is a host for.
        :param include_past: include events that have already ended.
        """
        # TODO: the only reason "events_" is in the name of this function is because "hosted" conflicts with the
        # backref name that it uses... find a way to be cleaner about that.
        events = self.hosted.order_by(desc(Event.time))
        # TODO: can you see private events this way??
        if not include_past:
            now = datetime.datetime.utcnow()
            events = events.filter(
                #Event.time < now,
                Event.ended == False,
                ((Event.end_time == None) & (now - EVENT_LENGTH < Event.time + AFTER_END_VISIBILITY)) | ((Event.end_time != None) & (now < Event.end_time + AFTER_END_VISIBILITY)),
            )
        return events.all()

    def search(self, query: str):
        users = User.query.filter(User.school_id == self.school_id,
                                  User.id != self.id,
                                  User.name.ilike('%' + query + '%'),
                                  User.confirmed == True)
        return users.limit(10).all()

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
        return self.friended.union(self.frienders).all()

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
        """
        Have I received a friend request from the given user?
        """
        return self.friend_requests_received.filter(friend_requests.c.friender_id == user.id).count() > 0

    def has_sent_friend_request(self, user) -> bool:
        """
        Have I sent a friend request from the given user?
        """
        return self.friend_requests_sent.filter(friend_requests.c.friended_id == user.id).count() > 0

    def has_friend_request(self, user) -> bool:
        """
        Return whether there is an active friend request (received or sent) to the given user.
        """
        return self.has_received_friend_request(user) or self.has_sent_friend_request(user)

    def feed(self):
        my_closed_events = self.hosted.filter_by(open=False)
        invited_closed_events = self.invited_to.filter_by(open=False)
        closed_events = my_closed_events.union(invited_closed_events)
        open_events = Event.query.filter_by(
            open=True,
            school_id=self.school_id
        )
        events = closed_events.union(open_events)
        # Filter out events that are over
        now = datetime.datetime.utcnow()
        events = events.filter(
            Event.time < now + UPCOMING_RANGE,
            Event.ended == False,
            ((Event.end_time == None) & (now - EVENT_LENGTH < Event.time)) | ((Event.end_time != None) & (now < Event.end_time)),
        )
        # Put private events first
        events = events.order_by(Event.time, Event.open)
        return events.all()

    def review_on(self, event, positive, negative, body):
        review = event.get_review(self)
        if review is None:
            review = Review(self, event)
            self.reviews.append(review)
        review.positive = positive
        review.negative = negative
        review.body = body

    def unreview_on(self, event):
        review = event.get_review(self)
        if review is None:
            return False
        db.session.delete(review)

    def is_blocking(self, user):
        return self.blocked.filter(blocks.c.blocked_id == user.id).count() > 0

    def facebook_connect(self, facebook_id, facebook_name):
        self.facebook_id = facebook_id
        self.facebook_name = facebook_name

    def facebook_disconnect(self):
        self.facebook_id = None
        self.facebook_name = None

    def facebook_friends(self):
        """
        Find Facebook friends of this user who are also registered.
        """
        # Facebook will only return friends who also use this app.
        friends = facebook.get_friends(self.facebook_id)
        facebook_ids = [user['id'] for user in friends]
        # TODO: don't build this list with python! There must be a better way to do this with a query...
        friend_ids = [user.id for user in self.friends()]
        users = User.query.filter(User.facebook_id.in_(facebook_ids) & User.id.notin_(friend_ids))
        return users.all()

    def json(self, me, event=None, need_friendship=True, is_friend=None, has_sent_friend_request=None, has_received_friend_request=None):
        """
        Generate JSON representation of this user.

        :param me: User currently logged in. Necessary to generate boolean fields describing relationships.
        :param event: optionally specify an event to check invitation status for.
        """
        raw = {key: getattr(self, key) for key in ('id', 'email', 'verified',
                                                   'facebook_id', 'facebook_name')}
        raw['name'] = self.facebook_name if self.facebook_name else self.name
        is_me = (self == me)
        raw.update({
            # Is this user me?
            'is_me': is_me,
            # Did this user receive/send a friend request from/to this user?
            'invited': event.is_invited(self) if event else None,
            'hosting': event.is_hosted_by(self) if event else None,
            'facebook_id': self.facebook_id,
            'facebook_name': self.facebook_name,
        })
        if need_friendship:
            if is_me:
                is_friend = False
                has_sent_friend_request = False
                has_received_friend_request = False
            else:
                if is_friend is None:
                    is_friend = self.is_friends_with(me)
                if is_friend:
                    has_sent_friend_request = False
                    has_received_friend_request = False
                if has_sent_friend_request is None:
                    has_sent_friend_request = self.has_sent_friend_request(me)
                if not has_sent_friend_request and has_received_friend_request is None:
                    has_received_friend_request = self.has_received_friend_request(me)
            raw.update({
                # Is the current user friends with this user?
                'is_friend': is_friend,
                'has_sent_friend_request': has_sent_friend_request,
                'has_received_friend_request': has_received_friend_request,
            })
        return raw


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

    # Location
    location = db.Column(db.String(100), nullable=False)
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    address = db.Column(db.String(256), nullable=True)

    image = db.Column(db.String(100))
    open = db.Column(db.Boolean, default=True)
    transitive_invites = db.Column(db.Boolean, default=False)
    capacity = db.Column(db.Integer)

    time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=True)
    ended = db.Column(db.Boolean, default=False)

    venmo = db.Column(db.String(16), nullable=True)
    alcohol = db.Column(db.Boolean, default=False)

    # Relationships
    school_id = db.Column(db.Integer, db.ForeignKey('schools.id'))
    hosts = db.relationship(
        'User', secondary=hostships,
        backref=db.backref('hosted', lazy='dynamic'), lazy='dynamic')
    #invitees = db.relationship('User', secondary='invitations', backref=db.backref('invited_to', lazy='dynamic'), lazy='dynamic')
    updates = db.relationship('Update', backref='event', lazy=True)
    reviews = db.relationship('Review', backref='event', lazy=True)

    def update(self, raw):
        """
        Take dictionary of raw data and use it to set fields.
        """
        self.time = datetime.datetime.fromisoformat(raw.pop('time'))
        self.time = self.time.astimezone(datetime.timezone.utc)
        raw_end_time = raw.pop('end_time', None)
        if raw_end_time:
            self.end_time = datetime.datetime.fromisoformat(raw_end_time)
            self.end_time = self.end_time.astimezone(datetime.timezone.utc)
        # TODO use set?
        for field in ('name', 'description', 'location', 'lat', 'lng', 'address', 'image',
                      'open', 'capacity', 'transitive_invites', 'venmo', 'alcohol'):
            if field in raw:
                setattr(self, field, raw[field])

    def __init__(self, raw, school_id):
        self.update(raw)
        self.registered_on = datetime.datetime.utcnow()
        self.school_id = school_id

    def add_host(self, user):
        if self.is_hosted_by(user):
            return False
        self.hosts.append(user)
        return True

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
        self.invites.append(user)
        return True

    def is_invited(self, user) -> bool:
        """
        Return whether there is an invitation to this event for the given user.
        """
        return self.invites.filter(invitations.c.user_id == user.id).count() > 0

    def has_tag(self, tag_name) -> bool:
        return self.tags.filter(taggings.c.tag_name == tag_name).count() > 0

    def add_tag(self, tag_name) -> bool:
        tag = Tag.query.get(tag_name)
        # Do we need to create the tag in the database?
        if tag is None:
            # Fail if the tag is blacklisted
            with open('resources/tag_blacklist.txt', 'r') as f:
                if tag in f.readlines():
                    return False
            tag = Tag(tag_name)
            db.session.add(tag)
        self.tags.append(tag)
        return True

    def remove_tag(self, tag_name) -> bool:
        tag = Tag.query.get(tag_name)
        self.tags.remove(tag)
        return True

    def happening_now(self):
        # TODO: don't get time every repetition
        now = datetime.datetime.utcnow()
        has_started = (self.time < now)
        has_not_been_ended = (not self.ended)
        is_not_over = (now < (self.end_time or (self.time + EVENT_LENGTH)))
        return (has_started and is_not_over and has_not_been_ended)

    def people(self):
        return User.query.filter(User.current_event_id == self.id).count()

    def get_review(self, user):
        return Review.query.filter(Review.event_id == self.id,
                                   Review.user_id == user.id).first()

    def rating(self):
        reviews = Review.query.filter(Review.event_id == self.id)
        reviews_count = reviews.count()
        if reviews_count == 0:
            return 5

        likes_count = reviews.filter(Review.positive == True).count()
        neutral_count = reviews.filter(Review.positive == False,
                               Review.negative == False).count()
        dislikes_count = reviews.filter(Review.negative == True).count()

        return round((5 * likes_count + 3 * neutral_count + 1 * dislikes_count) / reviews_count, 1)

    def json(self, me):
        raw = {key: getattr(self, key) for key in ('id', 'name', 'description', 'image',
                                                   'location', 'address', 'lat', 'lng',
                                                   'open', 'transitive_invites',
                                                   'capacity', 'venmo', 'alcohol')}
        review = self.get_review(me)
        raw.update({
            'time': self.time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'happening_now': self.happening_now(),
            'mine': me.admin or self.is_hosted_by(me),
            'invited_me': self.is_invited(me),
            'people': self.people(),
            'review': review.json() if review else None,
            'rating': self.rating(),
            'hosts': [host.json(me, need_friendship=False) for host in self.hosts],
            'tags': [tag.name for tag in self.tags],
        })
        return raw


class Invitation(db.Model):
    __tablename__ = 'invitations'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)


class Tag(db.Model):
    __tablename__ = 'tags'

    name = db.Column(db.String(32), primary_key=True)

    events = db.relationship(
        'Event', secondary=taggings,
        backref=db.backref('tags', lazy='dynamic'), lazy='dynamic'
    )

    def __init__(self, name):
        self.name = name


class Update(db.Model):
    __tablename__ = 'updates'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    body = db.Column(db.String(1024))

    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)

    def __init__(self, user, event):
        self.user_id = user.id
        self.event_id = event.id

    def json(self, me, include_event=False):
        raw = {
            'id': self.id,
            'body': self.body,
        }
        raw['user'] = self.user.json(me)
        if include_event:
            raw['event'] = self.event.json(me)
        return raw


class Review(db.Model):
    __tablename__ = 'reviews'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    positive = db.Column(db.Boolean)
    negative = db.Column(db.Boolean)
    body = db.Column(db.String(1024))

    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)

    def __init__(self, user, event):
        self.user_id = user.id
        self.event_id = event.id

    def json(self):
        return {
            'positive': self.positive,
            'negative': self.negative,
            'body': self.body,
        }


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
