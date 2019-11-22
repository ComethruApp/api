from flask import jsonify

def succ(message):
    return jsonify({
        'status': 'success',
        'message': message,
    })

def fail(message):
    return jsonify({
        'status': 'fail',
        'message': message,
    })
