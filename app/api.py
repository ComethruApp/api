from flask import Blueprint, jsonify, request, abort, g
from app import db
from app.models import User, Event

api_blueprint = Blueprint('api', __name__)


@api_blueprint.errorhandler(404)
def not_found_error(error):
    return jsonify({'status': 'fail', 'error': 'Not found.'}), 404

@api_blueprint.errorhandler(401)
def unauthorized(error):
    return jsonify({'status': 'fail', 'error': 'You don\'t have permission to do this.'}), 401

def verify_token():
    try:
        token = request.headers.get('Authorization').split(" ")[1]
        g.me = User.from_token(token)
    except IndexError:
        return jsonify({
            'status': 'fail',
            'message': 'Bearer token malformed.'
        }), 401
    if g.me is None:
        abort(401)

api_blueprint.before_request(verify_token)

@api_blueprint.route('/users/<user_id>')
def get_user(user_id):
    user = User.query.get(user_id)
    if user is None:
        abort(404)

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
    event = Event(data)
    db.session.add(event)
    db.session.commit()
    return jsonify(event.json())
