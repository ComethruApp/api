from flask import redirect
from app import app


@app.route('/')
def index():
    # TODO: proper domain redirect
    return redirect('https://comethru.io')
