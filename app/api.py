from flask import Blueprint, jsonify, request, abort, g
from app import db
from app.models import User, Event, School, friendships, friend_requests
from app.geography import attending
from app.util import succ, fail
import os

api = Blueprint('api', __name__)


@api.errorhandler(404)
def not_found_error(error):
    return fail('Not found.', 404)

@api.errorhandler(401)
def unauthorized(error):
    return fail('You\'re not authorized to perform this action.', 401)

@api.errorhandler(403)
def forbidden(error):
    return fail('You don\'t have permission to do this.', 403)

@api.before_request
def verify_token():
    g.me = User.from_token(request.args.get('token'))
    if g.me is None:
        abort(401)


###########################
# Lifecycle/miscellaneous #
###########################

@api.route('/heartbeat')
def heartbeat():
    return jsonify({
        'maintenance': bool(os.environ.get('MAINTENANCE', False)),
        'min_version': 0,
    })

@api.route('/location', methods=['POST'])
def update_location():
    payload = request.get_json(g.me)
    # TODO: this is massively inefficient
    g.me.current_event_id = None
    for event in g.me.feed():
        if attending(payload['lat'], payload['lng'], event.lat, event.lng):
            g.me.current_event_id = event.id
    db.session.commit()
    return succ('Location received!')


#########
# Users #
#########

@api.route('/users/<user_id>')
def get_user(user_id):
    user = User.query.get_or_404(user_id)
    return jsonify(user.json(g.me))

@api.route('/users/me')
def get_me():
    return jsonify(g.me.json(g.me))

@api.route('/users/me', methods=['PUT'])
def update_me():
    data = request.get_json()
    # TODO: make method of User
    g.me.name = data['name']
    db.session.commit()
    return succ('Updated profile.')

@api.route('/users/me/password', methods=['PUT'])
def update_password():
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    if not old_password or not new_password:
        return fail('Improper parameters.')
    if g.me.is_password_correct(old_password):
        g.me.set_password(new_password)
        db.session.commit()
        return succ('Successfully updated password!')
    return fail('Incorrect password.', 403)

@api.route('/users/search/<query>')
def search_users(query):
    users = g.me.search(query)
    return jsonify([user.json(g.me) for user in users])

@api.route('/users/<user_id>/block', methods=['POST'])
def block_user(user_id):
    user = User.query.get(user_id)
    if g.me.block(user):
        db.session.commit()
        return succ('Succesfully blocked user.')
    else:
        return fail('You\'ve already blocked this person.')

@api.route('/users/<user_id>/unblock', methods=['POST'])
def unblock_user(user_id):
    user = User.query.get(user_id)
    if g.me.unblock(user):
        db.session.commit()
        return succ('Succesfully unblocked user.')
    else:
        return fail('You haven\'t blocked this person.')

# Facebook
@api.route('/users/me/facebook', methods=['POST'])
def facebook_connect():
    data = request.get_json()
    g.me.facebook_connect(data['id'], data['name'])
    db.session.commit()
    return succ('Successfully connected!')

@api.route('/users/me/facebook', methods=['DELETE'])
def facebook_disconnect():
    g.me.facebook_disconnect()
    db.session.commit()
    return succ('Successfully disconnected!')

# Friendships
@api.route('/friends/<user_id>/request', methods=['POST'])
def create_friend_request(user_id):
    user = User.query.get_or_404(user_id)
    if g.me.friend_request(user):
        db.session.commit()
        return succ('Succesfully sent friend request!')
    else:
        return fail('You\'re already friends with this person.')

@api.route('/friends/<user_id>/cancel', methods=['POST'])
def cancel_friend_request(user_id):
    friend_request_sent = g.me.friend_requests_sent.filter(friend_requests.c.friended_id == user_id).first_or_404()
    if friend_request_sent is not None:
        g.me.friend_requests_sent.remove(friend_request_sent)
    db.session.commit()
    return succ('Succesfully cancelled friend request.')

@api.route('/friends/<friender_id>/accept', methods=['POST'])
def accept_friend_request(friender_id):
    req = g.me.friend_requests_received.filter(friend_requests.c.friender_id == friender_id).first_or_404()
    friend = User.query.get(friender_id)
    friend.friended.append(g.me)
    g.me.friend_requests_received.remove(req)
    db.session.commit()
    return succ('Accepted the request!')

@api.route('/friends/<user_id>/reject', methods=['POST'])
def reject_friend_request(user_id):
    """
    Decline a friend request.
    """
    req = g.me.friend_requests_received.filter(friend_requests.c.friender_id == user_id).first_or_404()
    g.me.friend_requests_received.remove(req)
    db.session.commit()
    return succ('Successfully rejected request.')

@api.route('/friends/<user_id>/remove', methods=['POST'])
def friend_remove(user_id):
    """
    Remove friendship.
    """
    friendship_sent = g.me.friended.filter(friendships.c.friended_id == user_id).first()
    friendship_received = g.me.frienders.filter(friendships.c.friender_id == user_id).first()
    if friendship_sent is None and friendship_received is None:
        return fail('Couldn\'t find a friendship with this person.')
    if friendship_sent is not None:
        g.me.friended.remove(friendship_sent)
    if friendship_received is not None:
        g.me.frienders.remove(friendship_received)
    db.session.commit()
    return succ('Succesfully removed friend.')

@api.route('/friends')
def get_friends():
    """
    Get friends of logged in user.
    """
    friends = g.me.friends()
    return jsonify([user.json(g.me) for user in friends])

@api.route('/friends/requests')
def get_friend_requests():
    """
    Get friend requests that have been sent to the current user.
    """
    friend_requests = g.me.friend_requests()
    return jsonify([user.json(g.me) for user in friend_requests])

##########
# Events #
##########

@api.route('/events')
def get_events():
    events = g.me.feed()
    return jsonify([event.json(g.me) for event in events])

@api.route('/events/<event_id>')
def get_event(event_id):
    event = Event.query.get_or_404(event_id)
    return jsonify(event.json(g.me))

@api.route('/events', methods=['POST'])
def create_event():
    data = request.get_json(g.me)
    event = Event(data, school_id=g.me.school_id)
    event.hosts = [g.me]
    db.session.add(event)
    db.session.commit()
    return jsonify(event.json(g.me))

@api.route('/events/<event_id>', methods=['PUT'])
def update_event(event_id):
    data = request.get_json(g.me)
    event = Event.query.get_or_404(event_id)
    if not event.is_hosted_by(g.me):
        abort(403)
    # TODO: evaluate security concerns...
    for key, value in data.items():
        setattr(event, key, value)
    db.session.commit()
    return jsonify(event.json(g.me)), 202

@api.route('/events/<event_id>', methods=['DELETE'])
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    if not event.is_hosted_by(g.me):
        abort(403)
    # FIXME: this fails because we haven't gotten rid of the hostships
    db.session.delete(event)
    db.session.commit()
    return succ('Event deleted successfully.')

@api.route('/events/<event_id>/end', methods=['POST'])
def end_event(event_id):
    event = Event.query.get_or_404(event_id)
    if not event.is_hosted_by(g.me):
        abort(403)
    event.ended = True
    db.session.commit()
    return succ('Event ended successfully.')

@api.route('/users/me/events/current')
def get_my_current_event():
    if g.me.current_event_id is None:
        return jsonify(None)
    event = Event.query.get(g.me.current_event_id)
    if event is None:
        # TODO: this feels very weird! Look into it!
        return jsonify(None)
    return jsonify(event.json(g.me))

@api.route('/users/<user_id>/events/current')
def get_user_current_event(user_id):
    # TODO: this is so repetitive stop
    user = User.query.get(user_id)
    if not g.me.is_friends_with(user):
        return fail('You must be friends with this user to view their location.', 403)
    if user.current_event_id is None:
        return jsonify(None)
    event = Event.query.get(user.current_event_id)
    if event is None:
        return jsonify(None)
    return jsonify(event.json(g.me))

@api.route('/users/me/events')
def get_my_events():
    events = g.me.events_hosted()
    return jsonify([event.json(g.me) for event in events])

@api.route('/users/<user_id>/events')
def get_user_events(user_id):
    user = User.query.get_or_404(user_id)
    events = user.events_hosted()
    return jsonify([event.json(g.me) for event in events])

@api.route('/events/<event_id>/friends')
def get_friends_at_event(event_id):
    users = g.me.friends_at_event(event_id)
    return jsonify([user.json(g.me) for user in users])

# Reviews
@api.route('/events/<event_id>/votes', methods=['GET'])
def get_votes(event_id):
    event = Event.query.get_or_404(event_id)
    return jsonify([vote.json() for vote in event.votes])

@api.route('/events/<event_id>/vote', methods=['POST'])
def vote(event_id):
    # TODO: check that I have access to this event
    data = request.get_json()
    event = Event.query.get(event_id)
    if data['positive'] and data['negative']:
        fail('You can\'t vote positively and negatively at the same time.')
    g.me.vote_on(event, data['positive'], data['negative'], data['review'])
    db.session.commit()
    return succ('Voted successfully.')

@api.route('/events/<event_id>/vote', methods=['DELETE'])
def unvote(event_id):
    # TODO: check that I have access to this event
    event = Event.query.get_or_404(event_id)
    g.me.unvote_on(event)
    db.session.commit()
    return succ('Successfully unvoted.')

# Invites
@api.route('/events/<event_id>/invites')
def get_event_invites(event_id):
    event = Event.query.get_or_404(event_id)
    return jsonify([user.json(g.me, event) for user in event.invitees])

@api.route('/events/<event_id>/invites/<user_id>', methods=['POST'])
def send_invite(event_id, user_id):
    event = Event.query.get_or_404(event_id)
    user = User.query.get_or_404(user_id)
    # TODO: store who created an invitation, and allow users who aren't hosts to only remove their invitations
    if event.transitive_invites or event.is_hosted_by(g.me):
        # Check out that intuitive syntax. Glorious. Like washing machines.
        if event.invite(user):
            db.session.commit()
            return succ('Invited user.')
        else:
            return fail('User already invited.')
    else:
        abort(403)

@api.route('/events/<event_id>/invites/<user_id>', methods=['DELETE'])
def delete_invite(event_id, user_id):
    event = Event.query.get_or_404(event_id)
    user = User.query.get_or_404(user_id)
    # TODO: allow non-host users when transitive_invites is on to remove their own invitations but nobody elses
    if event.is_hosted_by(g.me):
        event.invitees.remove(user)
        db.session.commit()
        return succ('Cancelled invite.', 200)
    else:
        abort(403)

# Hosts
@api.route('/events/<event_id>/hosts')
def get_event_hosts(event_id):
    event = Event.query.get_or_404(event_id)
    return jsonify([user.json(g.me, event) for user in event.hosts])

@api.route('/events/<event_id>/hosts/<user_id>', methods=['POST'])
def add_host(event_id, user_id):
    event = Event.query.get_or_404(event_id)
    user = User.query.get_or_404(user_id)
    if event.is_hosted_by(g.me):
        if event.add_host(user):
            db.session.commit()
            return succ('Added host.')
        else:
            return fail('User is already a host.')
    else:
        abort(403)

@api.route('/events/<event_id>/hosts/<user_id>', methods=['DELETE'])
def delete_host(event_id, user_id):
    event = Event.query.get_or_404(event_id)
    user = User.query.get_or_404(user_id)
    if event.is_hosted_by(g.me) and user != g.me:
        # TODO: Add remove_host function on event
        event.hosts.remove(user)
        db.session.commit()
        return succ('Removed host.', 200)
    else:
        abort(403)

@api.route('/events/<event_id>/invites/search/<query>')
def search_users_for_event(event_id, query):
    """
    Search users and also return data about their invitation status to a given event.
    TODO: This feels like a really nasty hack and there's gotta be a better way to do this...
    """
    users = g.me.search(query)
    event = Event.query.get(event_id)
    return jsonify([user.json(g.me, event) for user in users])
