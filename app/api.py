from flask import Blueprint, jsonify, request, abort, g
from app import db
from app.models import User, Event, School, Tag, Update, friendships, friend_requests
from app.geography import attending
from app.util import succ, fail
from app.notifier import notifier
from app.facebook import facebook
import datetime
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
    if request.method != 'OPTIONS':
        token = request.headers.get('Authorization', request.args.get('token', None))
        g.me = User.from_token(token)
        if g.me is None:
            abort(401)
        g.me.last_seen = datetime.datetime.utcnow()
        db.session.commit()
        print('User: ' + g.me.name)
        g.json = request.get_json()


#################
# Miscellaneous #
#################

@api.route('/heartbeat')
def heartbeat():
    return jsonify({
        'maintenance': bool(os.environ.get('MAINTENANCE', False)),
        'min_version': 0,
    })

@api.route('/location', methods=['POST'])
def update_location():
    lat = g.json['lat']
    lng = g.json['lng']
    # In order to save some processing, first check if the user is still at their current event
    # (which they probably will be a decent percentage of the time).
    if g.me.current_event_id is not None:
        event = Event.query.get(g.me.current_event_id)
        if attending(lat, lng, event.lat, event.lng):
            return succ('Location received, no event change.')

    g.me.current_event_id = None
    for event in g.me.feed():
        if (event.lat is not None and event.lng is not None) and attending(lat, lng, event.lat, event.lng):
            g.me.current_event_id = event.id
            break
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
    return jsonify(g.me.json(g.me, need_friendship=False))

@api.route('/users/me', methods=['PUT'])
def update_me():
    # TODO: make method of User
    g.me.name = g.json['name']
    db.session.commit()
    return succ('Updated profile.')

@api.route('/users/me/password', methods=['PUT'])
def update_password():
    old_password = g.json.get('old_password')
    new_password = g.json.get('new_password')
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

# Blocks
@api.route('/users/<user_id>/block', methods=['POST'])
def block_user(user_id):
    user = User.query.get(user_id)
    if g.me.block(user):
        db.session.commit()
        return succ('Succesfully blocked user.')
    else:
        return fail('You\'ve already blocked this person.')

@api.route('/users/<user_id>/block', methods=['DELETE'])
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
    g.me.facebook_connect(g.json['id'], g.json['name'])
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
        notifier.friend_request(g.me, user)
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
    notifier.accept_friend_request(g.me, friend)
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
    return jsonify([user.json(g.me, is_friend=True) for user in friends])

@api.route('/friends/requests')
def get_friend_requests():
    """
    Get users who have sent friend requests to the current user.
    """
    friend_requests = g.me.friend_requests()
    return jsonify([user.json(g.me, is_friend=False, has_received_friend_request=False, has_sent_friend_request=True) for user in friend_requests])

@api.route('/friends/facebook', methods=['GET'])
def get_facebook_friends():
    """
    Get a list of users who have connected to Facebook and are friends with this user there.
    """
    if g.me.facebook_id is None:
        return jsonify([])
    users = g.me.facebook_friends()
    return jsonify([user.json(g.me) for user in users])

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
    event = Event(g.json, school_id=g.me.school_id)
    event.hosts = [g.me]
    db.session.add(event)
    db.session.commit()
    return jsonify(event.json(g.me))

@api.route('/events/<event_id>', methods=['PUT'])
def update_event(event_id):
    event = Event.query.get_or_404(event_id)
    if not event.is_hosted_by(g.me):
        abort(403)
    event.update(g.json)
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

@api.route('/events/<event_id>/tags/<tag_name>', methods=['POST'])
def add_tag(event_id, tag_name):
    event = Event.query.get_or_404(event_id)
    tag_name = tag_name.lower()
    if not event.is_hosted_by(g.me):
        abort(403)
    # First, check if the event already has this tag.
    if event.has_tag(tag_name):
        return fail('Event already has this tag.')
    if event.add_tag(tag_name):
        db.session.commit()
        return succ('Added tag!')
    # If the tag is blacklisted or there was another problem
    return fail('Tag not added.')

@api.route('/events/<event_id>/tags/<tag_name>', methods=['DELETE'])
def remove_tag(event_id, tag_name):
    event = Event.query.get_or_404(event_id)
    if not event.is_hosted_by(g.me):
        abort(403)
    if not event.has_tag(tag_name):
        return fail('Event does not have this tag.')
    if event.remove_tag(tag_name):
        db.session.commit()
        return succ('Removed tag.')
    # Should not be reached, but just in case.
    return fail('Tag not removed.')

@api.route('/tags/search/<query>')
def search_tags(query):
    query = query.lower()
    tags = Tag.query.filter(User.name.ilike('%' + query + '%'))
    return jsonify([tag.name for tag in tags])

@api.route('/events/facebook')
def facebook_events():
    events = facebook.get_events(g.me.facebook_id)
    return jsonify([event for event in events])

@api.route('/users/me/events/current')
def get_my_current_event():
    if g.me.current_event_id is None:
        return jsonify([])
    event = Event.query.get(g.me.current_event_id)
    if event is None:
        return jsonify([])
    return jsonify([event.json(g.me)])

@api.route('/users/<user_id>/events/current')
def get_user_current_event(user_id):
    # TODO: this is so repetitive stop
    user = User.query.get(user_id)
    if not g.me.is_friends_with(user):
        return fail('You must be friends with this user to view their location.', 403)
    if g.me.current_event_id is None:
        return jsonify([])
    event = Event.query.get(user.current_event_id)
    if event is None:
        return jsonify([])
    return jsonify([event.json(g.me)])

@api.route('/users/me/events')
def get_my_events():
    events = g.me.events_hosted(include_past=True)
    return jsonify([event.json(g.me) for event in events])

@api.route('/users/<user_id>/events')
def get_user_events(user_id):
    user = User.query.get_or_404(user_id)
    events = user.events_hosted(include_past=(g.me == user))
    return jsonify([event.json(g.me) for event in events])

@api.route('/events/<event_id>/friends')
def get_friends_at_event(event_id):
    users = g.me.friends_at_event(event_id)
    return jsonify([user.json(g.me) for user in users])

# Reviews
@api.route('/events/<event_id>/reviews', methods=['GET'])
def get_reviews(event_id):
    event = Event.query.get_or_404(event_id)
    return jsonify([review.json() for review in event.reviews])

@api.route('/events/<event_id>/reviews', methods=['POST'])
def create_review(event_id):
    # TODO: check that I have access to this event
    event = Event.query.get(event_id)
    if g.json['positive'] and g.json['negative']:
        fail('You can\'t review positively and negatively at the same time.')
    g.me.review_on(event, g.json['positive'], g.json['negative'], g.json['body'])
    db.session.commit()
    return succ('Reviewed successfully.')

@api.route('/events/<event_id>/reviews', methods=['DELETE'])
def delete_review(event_id):
    # TODO: check that I have access to this event
    event = Event.query.get_or_404(event_id)
    g.me.unreview_on(event)
    db.session.commit()
    return succ('Successfully unreviewd.')

# Invites
@api.route('/events/<event_id>/invites')
def get_event_invites(event_id):
    event = Event.query.get_or_404(event_id)
    return jsonify([user.json(g.me, event) for user in event.invites])

@api.route('/events/<event_id>/invites/<user_id>', methods=['POST'])
def send_invite(event_id, user_id):
    event = Event.query.get_or_404(event_id)
    user = User.query.get_or_404(user_id)
    # TODO: store who created an invitation, and allow users who aren't hosts to only remove their invitations
    if event.transitive_invites or event.is_hosted_by(g.me):
        if event.invite(user):
            db.session.commit()
            notifier.send_invite(event, user_from=g.me, user_to=user)
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
        event.invites.remove(user)
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

# Updates
@api.route('/events/<event_id>/updates')
def get_event_updates(event_id):
    event = Event.query.get_or_404(event_id)
    # TODO: Check that we have access
    return jsonify([update.json(g.me) for update in event.updates])

@api.route('/events/<event_id>/updates/<update_id>')
def get_event_update(event_id, update_id):
    #event = Event.query.get_or_404(event_id)
    update = Update.query.get_or_404(update_id)
    # TODO: Check that we have access
    return jsonify(update.json(g.me))

@api.route('/events/<event_id>/updates', methods=['POST'])
def create_event_update(event_id):
    event = Event.query.get_or_404(event_id)
    if event.is_hosted_by(g.me):
        update = Update(g.me, event)
        db.session.commit()
        # TODO: send notification to subscribed users
        return jsonify(update.json(g.me))
    else:
        abort(403)

@api.route('/events/<event_id>/updates/<update_id>', methods=['PUT'])
def update_event_update(event_id, update_id):
    event = Event.query.get_or_404(event_id)
    if event.is_hosted_by(g.me):
        update = Update.query.get_or_404(update_id)
        update.body = g.json['body']
        return jsonify(update.json(g.me))
    return fail('Could not edit update.')

@api.route('/events/<event_id>/delete/<update_id>', methods=['DELETE'])
def delete_update(event_id, update_id):
    event = Event.query.get_or_404(event_id)
    update = Update.query.get_or_404(update_id)
    if event.is_hosted_by(g.me):
        event.updates.remove(update)
        db.session.delete(update)
        db.session.commit()
        return succ('Deleted update.', 200)
    else:
        abort(403)
