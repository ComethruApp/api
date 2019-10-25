from flask import Blueprint, jsonify, request
from app import db
from app.models import User

api_blueprint = Blueprint('api', __name__)


"""
@api_blueprint.route('/bot/<slug>')
def api_bot(slug):
    # TODO: use a respectable 404
    token = request.args.get("token")
    if not token or token != bot.token:
        return {"error": "Missing or invalid token."}, 401
    bot = Bot.query.filter_by(slug=slug).first_or_404()
    return bot.json()


@api_blueprint.route('/bot/<slug>/instance/<group_id>')
def api_instance(slug, group_id):
    token = request.args.get("token")
    bot = Bot.query.filter_by(slug=slug).first_or_404()
    if not token or token != bot.token:
        return {"error": "Missing or invalid token."}
    instance = Instance.query.filter_by(bot_id=bot.id, group_id=group_id).first_or_404()
    return {"id": instance.id}
"""

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
