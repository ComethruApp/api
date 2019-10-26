from flask import Blueprint, jsonify, request
from app import db
from app.models import User

api_blueprint = Blueprint('api', __name__)


@api_blueprint.errorhandler(404)
def not_found_error(error):
    return jsonify({'status': 'fail'}), 404

@api_blueprint.route('/users/me')
def get_me():
    token = request.args.get('token')
    user_id = User.decode_token(token)
    user = User.query.get(user_id)
    if user:
        return jsonify(user.json())
    abort(404)
