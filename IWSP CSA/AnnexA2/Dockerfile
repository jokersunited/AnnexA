FROM python:3.8
COPY . /app
RUN apt-get -y update
RUN apt-get install -y google-chrome-stable
RUN python -m pip install -r /app/requirements.txt
CMD python /app/main.py