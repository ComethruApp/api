import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    WEB_DOMAIN = 'https://comethru.io'

    SECRET_KEY = os.environ.get('SECRET_KEY', 'Override this in production')
    SECURITY_PASSWORD_SALT = os.environ.get('SECURITY_PASSWORD_SALT', 'Override this too')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL',
                                             'sqlite:///' + os.path.join(basedir, 'app.db')).replace('postgres://', 'postgresql://')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    BCRYPT_LOG_ROUNDS = 13

    CONFIRMATION_TOKEN_EXPIRATION = 3600000

    # Email sending with Mailgun
    MAILGUN_API_KEY = os.environ['MAILGUN_API_KEY']
    MAILGUN_SENDER_NAME = 'Comethru'
    MAILGUN_SENDER = 'noreply@mail.comethru.io'

    # Email sending with Gmail (fallback)
    MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_PORT = 465
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    # Authentication
    MAIL_USERNAME = os.environ['APP_MAIL_USERNAME']
    MAIL_PASSWORD = os.environ['APP_MAIL_PASSWORD']

    # mail accounts
    MAIL_DEFAULT_SENDER = 'hello@comethru.io'

    ONESIGNAL_API_KEY = os.environ['ONESIGNAL_API_KEY']
    ONESIGNAL_APP_ID = os.environ['ONESIGNAL_APP_ID']

    FACEBOOK_APP_ID = os.environ['FACEBOOK_APP_ID']
    FACEBOOK_APP_SECRET = os.environ['FACEBOOK_APP_SECRET']
    FACEBOOK_API_TOKEN = os.environ['FACEBOOK_API_TOKEN']
