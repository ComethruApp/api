import requests
from app import app

def send_email(to, subject, html):
    return requests.post('https://api.mailgun.net/v3/mail.comethru.io/messages',
                         auth=('api', app.config['MAILGUN_API_KEY']),
                         data={'from': 'Comethru <hello@comethru.io>',
                               'to': [to],
                               'subject': subject,
                               'html': html})
