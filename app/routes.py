import requests
from flask import render_template, flash, redirect, url_for, request, abort, make_response
from app import app, db
from app.models import User


@app.route('/')
def index():
    return render_template('index.html')
