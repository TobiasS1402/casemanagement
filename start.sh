#!/bin/bash
# Start Redis server daemonized
redis-server --daemonize yes

# Start celery as background task
celery -A app.celery worker  &

# Run Flask app
gunicorn --bind 0.0.0.0:5000 --access-logfile - app:app