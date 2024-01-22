## Required Environment variables
- `SECRET_KEY` varchar(100) secret value for cookie "salt" in Flask
- `SECURITY_PASSWORD_SALT` varchar(100) secret value for password salting
- `SPLUNK_URL` url(`https://{ip}:{port}`) for Splunk api port 8089
- `SPLUNK_TOKEN` JWT for Splunk access via api as bearer
- `PROD_DB_STRING` PostgreSQL connection string as `postgesql://{username}:{password}@{hostname}:{port}/{database}?sslmode=require`

## Running dev by hand
```bash
pip install -r requirements.txt

env DEPLOYMENT="development" env SECRET_KEY="sadsadsad" env SECURITY_SALT_PASSWORD="asdasda" env SPLUNK_URL="https://127.0.0.1:8089" env SPLUNK_TOKEN="eyJra.." env python app.py
```

## Running prod by hand
```bash
pip install -r requirements.txt

env DEPLOYMENT="production" env SECRET_KEY="sadsadsad" env SECURITY_SALT_PASSWORD="asdasda" env SPLUNK_URL="https://127.0.0.1:8089" env SPLUNK_TOKEN="eyJra.." env PROD_DB_STRING="" gunicorn --bind 0.0.0.0:9000 --access-logfile - app:app
```


**Sources:**
- https://www.cloud-response.com/2019/07/importing-windows-event-log-files-into.html
- https://michael-gale.medium.com/upload-files-into-splunk-through-the-api-6aa9ca912545

