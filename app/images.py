import os
import requests
from base64 import b64decode

GROUPME_ACCESS_TOKEN = os.environ.get('GROUPME_ACCESS_TOKEN')


def image_upload(data) -> str:
    """
    Send image to GroupMe Image API.
    :param data: compressed image data.
    :return: URL of image now hosted on GroupMe server.
    """
    headers = {
        "X-Access-Token": ACCESS_TOKEN,
        "Content-Type": "image/jpeg",
    }
    r = requests.post("https://image.groupme.com/pictures", data=data, headers=headers)
    return r.json()["payload"]["url"]
