import requests
from app import app
#from app.models import User

class Notifier:
    def friend_request(self, user_from, user_to):
        r = requests.post('https://onesignal.com/api/v1/notifications',
                          json={
                                 'app_id': app.config['ONESIGNAL_APP_ID'],
                                 'included_segments': [],
                                 'include_external_user_ids': str(user_to.id),
                                 'headings': {'en': 'New friend request'},
                                 'contents': {'en': user_from.name + ' has sent you a friend request on Comethru.'},
                                 'data': {'task': 'TODO'},
                          },
                          headers={'Authorization': 'Basic ' + app.config['ONESIGNAL_API_KEY']})
        print(r.text)
        return r

notifier = Notifier()
