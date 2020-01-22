#!/usr/bin/env bash
# E501 Line too long
# E402 Import not at top of file
# E265 block comment should start with '# '
# E712 comparison to booleans; this is conventional in SQLAlchemy queries
# E126 continuation line over-indented for visual indent
# E128 continuation line under-indented for visual indent
pycodestyle *.py app/*.py --ignore=E501,E402,E265,E712,E126,E128
