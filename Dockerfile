FROM python:3.11-bullseye

WORKDIR /evidenceportal

COPY . /evidenceportal/

RUN pip3 install -r requirements.txt

EXPOSE 9000

CMD ["gunicorn","--bind","0.0.0.0:9000", "--access-logfile", "-", "app:app"]