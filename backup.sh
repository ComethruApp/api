#!/usr/bin/env bash

heroku pg:backups:capture
heroku pg:backups:download --output backups/$(date +%s).dump
