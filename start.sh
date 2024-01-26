#!/bin/bash

# Start Redis server
redis-server --daemonize yes

# Run Flask app
gunicorn --bind 0.0.0.0:9000 --access-logfile - app:app