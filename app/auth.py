from flask import Blueprint, request, make_response, jsonify
from flask.views import MethodView

from app import db, bcrypt
from app.models import User, BlacklistedToken

auth_blueprint = Blueprint('auth', __name__)

class RegisterAPI(MethodView):
    """
    User Registration Resource
    """
    def post(self):
        # get the post data
        post_data = request.get_json()
        # check if user already exists
        user = User.query.filter_by(email=post_data.get('email')).first()
        if not user:
            try:
                user = User(
                    name=post_data.get('name'),
                    email=post_data.get('email'),
                    password=post_data.get('password'),
                )

                # insert the user
                db.session.add(user)
                db.session.commit()
                # generate the auth token
                token, exp = user.encode_token(user.id)
                response_data = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'token': token.decode(),
                    # TODO: clean this up?
                    'user': {
                        'id': user.id,
                        'name': user.name,
                        # do we need this?
                        'email': user.email,
                        'token': token.decode(),
                        'expires_in': exp,
                    }
                }
                return make_response(jsonify(response_data)), 201
            except Exception as e:
                raise e
                response_data = {
                    'status': 'fail',
                    'message': 'Some error occurred. Please try again.'
                }
                return make_response(jsonify(response_data)), 401
        else:
            response_data = {
                'status': 'fail',
                'message': 'User already exists. Please Log in.',
            }
            return make_response(jsonify(response_data)), 202


class LoginAPI(MethodView):
    """
    User Login Resource
    """
    def post(self):
        # get the post data
        post_data = request.get_json()
        try:
            # fetch the user data
            user = User.query.filter_by(
                email=post_data.get('email')
            ).first()
            if user and bcrypt.check_password_hash(user.password, post_data.get('password')):
                # TODO stop abusing this function, it should just return one thing
                token, exp = user.encode_token(user.id)
                if token:
                    response_data = {
                        'status': 'success',
                        'message': 'Successfully logged in.',
                        'token': token.decode(),
                        # TODO: clean this up?
                        'user': {
                            'id': user.id,
                            'name': user.name,
                            # do we need this?
                            'email': user.email,
                            'token': token.decode(),
                            'expires_in': exp,
                        }
                    }
                    return make_response(jsonify(response_data)), 200
            else:
                response_data = {
                    'status': 'fail',
                    'message': 'User does not exist.'
                }
                return make_response(jsonify(response_data)), 404
        except Exception as e:
            print(e)
            response_data = {
                'status': 'fail',
                'message': 'Try again'
            }
            return make_response(jsonify(response_data)), 500


class UserAPI(MethodView):
    """
    User Resource
    """
    def get(self):
        # get the auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                response_data = {
                    'status': 'fail',
                    'message': 'Bearer token malformed.'
                }
                return make_response(jsonify(response_data)), 401
        else:
            token = ''
        if token:
            resp = User.decode_token(token)
            if not isinstance(resp, str):
                user = User.query.filter_by(id=resp).first()
                response_data = {
                    'status': 'success',
                    'data': {
                        'user_id': user.id,
                        'email': user.email,
                        'admin': user.admin,
                        'registered_on': user.registered_on
                    }
                }
                return make_response(jsonify(response_data)), 200
            response_data = {
                'status': 'fail',
                'message': resp
            }
            return make_response(jsonify(response_data)), 401
        else:
            response_data = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(response_data)), 401


class LogoutAPI(MethodView):
    """
    Logout Resource
    """
    def post(self):
        # get auth token
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(" ")[1]
        else:
            token = ''
        if token:
            resp = User.decode_token(token)
            if not isinstance(resp, str):
                # mark the token as blacklisted
                blacklisted_token = BlacklistedToken(token=token)
                try:
                    # insert the token
                    db.session.add(blacklisted_token)
                    db.session.commit()
                    response_data = {
                        'status': 'success',
                        'message': 'Successfully logged out.'
                    }
                    return make_response(jsonify(response_data)), 200
                except Exception as e:
                    response_data = {
                        'status': 'fail',
                        'message': e
                    }
                    return make_response(jsonify(response_data)), 200
            else:
                response_data = {
                    'status': 'fail',
                    'message': resp
                }
                return make_response(jsonify(response_data)), 401
        else:
            response_data = {
                'status': 'fail',
                'message': 'Provide a valid auth token.'
            }
            return make_response(jsonify(response_data)), 403


# define the API resources
registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
user_view = UserAPI.as_view('user_api')
logout_view = LogoutAPI.as_view('logout_api')

# add Rules for API Endpoints
auth_blueprint.add_url_rule(
    '/register',
    view_func=registration_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/login',
    view_func=login_view,
    methods=['POST']
)
auth_blueprint.add_url_rule(
    '/status',
    view_func=user_view,
    methods=['GET']
)
auth_blueprint.add_url_rule(
    '/logout',
    view_func=logout_view,
    methods=['POST']
)
