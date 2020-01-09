from flask import render_template
from app import app, db
from app.models import User

@app.route('/stats')
def stats():
    return render_template('stats.html', users=User.query.count())
