# casemanagement - Forensic case management

casemanagement is a Python Flask-powered application designed to streamline the management of forensic cases. It provides an intuitive interface for investigators to upload evidence and receive the analyzed results.

## Features

- **Case Management**: Easily create, update, and delete forensic cases.
- **Evidence Tracking**: Upload and analyze forensic case data.
- **User Authentication**: Secure user authentication and authorization system.
- **Automatic reporting**: Automatically send analyzed data to Splunk backend.
- **Customizable**: Adapt the application to fit your specific forensic investigation workflow.

## Screenshots
_to do_

## Environment Variables

To run the application, you need to set the following environment variables:
- **DEPLOYMENT**: development creates a local sqlite db, value production expects **PROD_DB_STRING** to be set
- **SECRET_KEY**: varchar(100) secret value for cookie "salt" in Flask
- **SECURITY_PASSWORD_SALT**: varchar(100) secret value for password salting
- **SPLUNK_URL**: url(`https://{ip}:{port}`) for Splunk api port 8089
- **SPLUNK_TOKEN**: JWT for Splunk access via api as bearer
- **PROD_DB_STRING**: PostgreSQL connection string as `postgesql://{username}:{password}@{hostname}:{port}/{database}?sslmode=require`
- **ADMIN_PASSWORD**: Admin user password
- **ADMIN_EMAIL**: Admin user emailaddress
- **HAYABUSA_WORKER_URL**: Hayabusa worker url with /upload _[explained further down below]_
- **HAYABUSA_ACCESS_TOKEN**: Hayabusa accesstoken for the workers _[explained further down below]_


## Installation (ghcr.io)

1. Pull image:
```
docker pull ghcr.io/tobiass1402/casemanagement:main
```

2. Set-up docker-compose

```bash
cp docker-compose-example.yml docker-compose.yml
```

3. Edit variables

4. Run

```bash
docker compose up
```

## Installation (build yourself)

1. Clone the repository:

```bash
git clone https://github.com/tobiass1402/casemanagement
cd casemanagement
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set-up docker-compose

```bash
cp docker-compose-example.yml docker-compose.yml
```

4. Edit variables

5. Run and build

```bash
docker compose up --build 
```


The application should now be running and accessible at `http://0.0.0.0:9000`.

## Hayabusa worker
In order to automatically have your `.evtx` files analyzed you need to set-up the Hayabusa worker from https://github.com/TobiasS1402/hayabusa-docker. 
This has automatically been added to docker-compose, just set the same key for **HAYABUSA_ACCESS_TOKEN** and **ACCESS_TOKEN**.

## Contributing

Contributions are welcome! If you have any suggestions, feature requests, or bug reports, please open an issue or submit a pull request.

## To do list
- [ ] seperate Celery task files
- [ ] seperate files for functions and classes
- [ ] create error view for tasks
- [ ] create retry button for failed tasks
- [ ] create database connection task storage
