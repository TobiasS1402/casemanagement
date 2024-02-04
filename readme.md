# v1.0 - Async workers

## Required Environment variables
- `SECRET_KEY` varchar(100) secret value for cookie "salt" in Flask
- `SECURITY_PASSWORD_SALT` varchar(100) secret value for password salting
- `SPLUNK_URL` url(`https://{ip}:{port}`) for Splunk api port 8089
- `SPLUNK_TOKEN` JWT for Splunk access via api as bearer
- `PROD_DB_STRING` PostgreSQL connection string as `postgesql://{username}:{password}@{hostname}:{port}/{database}?sslmode=require`
- `ADMIN_PASSWORD` Admin user password
- `ADMIN_EMAIL` Admin user emailaddress
- `HAYABUSA_WORKER_URL` Hayabusa worker url with /upload
- `HAYABUSA_ACCESS_TOKEN` Hayabusa accesstoken for the workers

## Running dev with docker-compose
set `DEPLOYMENT: development`
```docker
docker compose up -d 
```

## Running prod with docker-compose
set `DEPLOYMENT: production`
set `PROD_DB_STRING: [url]`
```docker
docker compose up -d 
```


**Sources:**
- https://www.cloud-response.com/2019/07/importing-windows-event-log-files-into.html
- https://michael-gale.medium.com/upload-files-into-splunk-through-the-api-6aa9ca912545



## To do list
- [ ] seperate Celery task files
- [ ] seperate files for functions and classes
- [ ] create error view for tasks
- [ ] create retry button for failed tasks
- [ ] create database connection task storage
