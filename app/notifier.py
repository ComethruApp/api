import requests
from app import app
#from app.models import User

class Notifier:
    def _send(to, heading: str, content: str, data: dict):
        """
        Send a notification to OneSignal's API.

        :param to: list of internal user IDs to send to, or a single ID.
        :param heading: heading to use in notification.
        :param content: text content of notification.
        :param data: other data to be delivered with notification.
        """
        if not isinstance(to, list):
            to = [to]
        to = [str(user_id) for user_id in to]
        r = requests.post('https://onesignal.com/api/v1/notifications',
                          json={
                                 'app_id': app.config['ONESIGNAL_APP_ID'],
                                 'included_segments': [],
                                 'include_external_user_ids': to,
                                 'headings': {'en': header},
                                 'contents': {'en': content},
                                 'data': data,
                          },
                          headers={'Authorization': 'Basic ' + app.config['ONESIGNAL_API_KEY']})
        return r.ok

    def friend_request(self, user_from, user_to):
        return self._send(user_to.id,
                          heading='New friend request',
                          content=user_from.name + ' has sent you a friend request.',
                          data={'task': 'TODO'})

    def accept_friend_request(self, user_from, user_to):
        return self._send(user_to.id,
                          heading='Friend request accepted',
                          content=user_from.name + ' is now your friend.',
                          data={'task': 'TODO'})

    def send_invite(self, event, user_from, user_to):
        return self._send(user_to.id,
                          heading='You\re invited!',
                          content=user_from.name + ' has invited you to ' + event.name + '! Come thru!',
                          data={'task': 'TODO'})

notifier = Notifier()
