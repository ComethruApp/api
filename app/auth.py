from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from app import db
from app.models import User

auth_blueprint = Blueprint('auth', __name__)
