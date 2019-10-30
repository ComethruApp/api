import logging
from logging.handlers import SMTPHandler, RotatingFileHandler
import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_mail import Mail
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_seeder import FlaskSeeder
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
app.testing = False
CORS(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
bcrypt = Bcrypt(app)
seeder = FlaskSeeder()
seeder.init_app(app, db)

if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240,
                                       backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    app.logger.setLevel(logging.INFO)
    app.logger.info('App startup')

from app import routes, models, api, auth
app.register_blueprint(api.api_blueprint, url_prefix='/api')
app.register_blueprint(auth.auth_blueprint, url_prefix='/auth')
