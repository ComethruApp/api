from flask import Blueprint, jsonify, request, abort, g
from app import db
from app.models import User, Event
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
    users = User.query.filter(User.id != g.me.id, User.name.like('%' + query + '%')).all()
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


@api_blueprint.route('/location/<float:lat>/<float:lng>', methods=['POST'])
def update_location(lat, lng):
    g.me.lat = lat
    g.me.lng = lng
    # TODO: this is massively inefficient
    now = datetime.datetime.now()
    for event in Event.query.filter(Event.time < now < Event.time + datetime.timedelta(hours=5)):
        if attending(lat, lng, Event.lat, Event.lng):
            g.me.current_event_id = event.id
    db.session.commit()
