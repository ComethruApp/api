from flask import Blueprint, jsonify, request, abort, g
from app import db
from app.models import User, Event, friendships, friend_requests
from app.geography import attending

api_blueprint = Blueprint('api', __name__)


@api_blueprint.errorhandler(404)
def not_found_error(error):
    return jsonify({'status': 'fail', 'message': 'Not found.'}), 404

@api_blueprint.errorhandler(401)
def unauthorized(error):
    return jsonify({'status': 'fail', 'message': 'You don\'t have permission to do this.'}), 401

@api_blueprint.before_request
def verify_token():
    g.me = User.from_token(request.args.get('token'))
    if g.me is None:
        abort(401)

@api_blueprint.route('/users/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    if user is None:
        abort(404)

@api_blueprint.route('/users/search/<query>')
def search_users(query):
    users = User.query.filter(User.id != g.me.id, User.name.ilike('%' + query + '%')).all()
    return jsonify([user.json() for user in users])

@api_blueprint.route('/users/me')
def get_me():
    return jsonify(g.me.json())

@api_blueprint.route('/events')
def get_events():
    events = Event.query.all()
    return jsonify([event.json() for event in events])

@api_blueprint.route('/events/<event_id>')
def get_event(event_id):
    event = Event.query.get(event_id)
    if event is None:
        abort(404)
    return jsonify(event.json())

@api_blueprint.route('/events', methods=['POST'])
def create_event():
    data = request.get_json()
    event = Event(data, school_id=g.me.school_id)
    event.add_host(g.me)
    db.session.add(event)
    db.session.commit()
    return jsonify(event.json())

@api_blueprint.route('/events/<event_id>', methods=['DELETE'])
def delete_event(event_id):
    event = Event.query.get(event_id)
    if event is None:
        abort(404)
    if event.hosted_by(g.me):
        abort(401)
    # FIXME: this fails because we haven't gotten rid of the hostships
    db.session.delete(event)
    db.session.commit()
    return jsonify({
        'status': 'success',
        'message': 'Event deleted successfully.',
    }), 200


@api_blueprint.route('/location', methods=['POST'])
def update_location():
    payload = request.get_json()
    g.me.lat = payload['lat']
    g.me.lng = payload['lng']
    # TODO: this is massively inefficient
    now = datetime.datetime.now()
    for event in Event.query.filter(Event.time < now < Event.time + datetime.timedelta(hours=5)):
        if attending(lat, lng, Event.lat, Event.lng):
            g.me.current_event_id = event.id
    db.session.commit()

@api_blueprint.route('/friends/request/<target_id>', methods=['POST'])
def friend_request(target_id):
    target = User.query.get(target_id)
    if g.me.friend_request(target):
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Succesfully sent friend request!',
        }), 201
    else:
        return jsonify({
            'status': 'fail',
            'message': 'You\'re already friends with this person.',
        }), 400

@api_blueprint.route('/friends/accept/<friender_id>', methods=['POST'])
def friend_accept(friender_id):
    req = g.me.friend_requests_received.filter(friend_requests.c.friender_id == friender_id).first()
    if req is None:
        return jsonify({
            'status': 'fail',
            'message': 'This person hasn\'t sent you a friend request.',
        }), 400
    else:
        friend = User.query.get(friender_id)
        friend.friended.append(g.me)
        g.me.friend_requests_received.remove(req)
        db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Accepted the request!',
        }), 200

@api_blueprint.route('/friends/remove/<user_id>', methods=['POST'])
def friend_remove(user_id):
    """
    Remove friend request or friendship.
    """
    friendship = Friendship.query.filter(Friendship.user_id_from == user_id and Friendship.user_id_to == g.me.id \
                                      or Friendship.user_it_from == g.me.id and Friendship.user_it_to == user_id).first()
    if friendship is None:
        return jsonify({
            'status': 'fail',
            'message': 'Couldn\'t find a friend request from this person.',
        }), 400

    db.session.delete(friendship)
    db.session.commit()
    return jsonify({
        'status': 'success',
        'message': 'Succesfully removed friend.',
    }), 200

@api_blueprint.route('/friends')
def get_friends():
    """
    Get friends of logged in user.
    """
    friends = g.me.friends()
    return jsonify([user.json() for user in friends]), 200

@api_blueprint.route('/friends/requests')
def get_friend_requests():
    """
    Get friend requests that have been sent to the current user.
    """
    friend_requests = g.me.friend_requests()
    return jsonify([user.json() for user in friend_requests])
