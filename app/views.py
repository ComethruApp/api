from flask import render_template, redirect
from app import app, db
from app.models import User


@app.route('/')
def index():
    # TODO: proper domain redirect
    return redirect('https://comethru.io')


@app.route('/stats')
def stats():
    return render_template('stats.html', users=User.query.count())
