from math import sin, cos, sqrt, atan2, radians

# Approximate radius of earth in kilometers
EARTH_RADIUS = 6373.0
# Max distance to consider as event attendance, in km
ATTENDANCE_THRESHOLD = 0.020


def distance(lat1, lng1, lat2, lng2):
    lat1 = radians(lat1)
    lng1 = radians(lng1)
    lat2 = radians(lat2)
    lng2 = radians(lng2)

    dlng = lng2 - lng1
    dlat = lat2 - lat1

    a = sin(dlat / 2)**2 + cos(lat1) * cos(lat2) * sin(dlng / 2)**2
    c = 2 * atan2(sqrt(a), sqrt(1 - a))

    distance = EARTH_RADIUS * c

    return distance


def attending(lat1, lng1, lat2, lng2):
    return (distance(lat1, lng1, lat2, lng2) < ATTENDANCE_THRESHOLD)
