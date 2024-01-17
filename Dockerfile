FROM 3.11-bullseye

WORKDIR /evidenceportal

COPY . /evidenceportal/

RUN pip3 install -r requirements.txt

CMD ["python3", "-m", "flask", "run", "--host=0.0.0.0"]