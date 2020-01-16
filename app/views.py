from flask import render_template
from app import app, db
from app.models import User

def email_to_name(email: str):
    email = email.split('@')[0]
    chunks = [chunk[0].upper() + chunk[1:] for chunk in email.split('.') if chunk.isalpha()]
    return ' '.join(chunks)

@app.route('/stats')
def stats():
    for user in User.query.all():
        if user.name == 'Name missing' or user.name == '':
            user.name = email_to_name(user.email)
    db.session.commit()
    return render_template('stats.html', users=User.query.count())
