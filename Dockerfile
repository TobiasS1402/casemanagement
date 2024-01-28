FROM python:3.11-bullseye

WORKDIR /evidenceportal

COPY . /evidenceportal/

RUN apt-get update && apt-get install -y redis-server

RUN pip3 install -r requirements.txt

RUN chmod +x start.sh

EXPOSE 5000

CMD ["./start.sh"]