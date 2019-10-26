#!/usr/bin/bash
rm -rf app.db migrations
flask db init && flask db migrate && flask db upgrade
