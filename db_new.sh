#!/usr/bin/env bash

git push heroku & git push
wait
heroku pg:reset DATABASE --confirm comethru
heroku run 'flask db upgrade'

# Previously, this just wiped our own database
#rm -rf app.db migrations
#flask db init && flask db migrate && flask db upgrade
