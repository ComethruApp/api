import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    WEB_DOMAIN = 'https://comethru.io'

    SECRET_KEY = os.environ.get('SECRET_KEY', 'Override this in production')
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT', 'Override this too')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL',
                                             'sqlite:///' + os.path.join(basedir, 'app.db'))
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    BCRYPT_LOG_ROUNDS = 13

    CONFIRMATION_TOKEN_EXPIRATION = 36000

    MAILGUN_API_KEY = os.environ['MAILGUN_API_KEY']
    MAILGUN_SENDER_NAME = 'Comethru'
    MAILGUN_SENDER = 'hello@comethru.io'
