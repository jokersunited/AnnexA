FROM python:3.8
COPY . /app
RUN python -m pip install -r /app/requirements.txt
RUN apt-get install -y google-chrome-stable
CMD python /app/main.py