import requests
from app import app


def send_email(to, subject, html):
    return requests.post('https://api.mailgun.net/v3/mail.comethru.io/messages',
                         auth=('api', app.config['MAILGUN_API_KEY']),
                         data={'from': '{name} <{address}>'.format(name=app.config['MAILGUN_SENDER_NAME'],
                                                                   address=app.config['MAILGUN_SENDER']),
                               'to': [to],
                               'subject': subject,
                               'html': html})
