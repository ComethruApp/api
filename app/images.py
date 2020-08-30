import os
import requests
from base64 import b64decode
from io import BytesIO

GROUPME_ACCESS_TOKEN = os.environ.get('GROUPME_ACCESS_TOKEN')


def image_upload(data) -> str:
    """
    Send image to GroupMe Image API.
    :param data: compressed image data.
    :return: URL of image now hosted on GroupMe server.
    """
    image = BytesIO(b64decode(data)).getvalue()
    headers = {
        'X-Access-Token': GROUPME_ACCESS_TOKEN,
        'Content-Type': 'image/jpeg',
    }
    r = requests.post('https://image.groupme.com/pictures', data=image, headers=headers)
    url = r.json()['payload']['url']
    return url
