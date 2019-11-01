#!/usr/bin/env bash

heroku pg:reset DATABASE --confirm comethru
heroku run 'flask db init; flask db migrate'

# Previously, this just wiped our own database
#rm -rf app.db migrations
#flask db init && flask db migrate && flask db upgrade
