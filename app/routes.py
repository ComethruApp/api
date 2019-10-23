import requests
from flask import render_template, flash, redirect, url_for, request, abort, make_response
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.urls import url_parse
from app import app, db
#from app.forms import BotForm, InstanceForm
from app.models import User


@app.route('/')
def index():
    return render_template('index.html')
