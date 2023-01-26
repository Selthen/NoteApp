FROM ubuntu:latest
WORKDIR /app
ENV APP_SECRET_KEY=j0Oc30S2BxT6rzkE9vOtHjWmsOIt8YGKYzenbZ3wafHgeIBHTgaiWmaJiqa2c7qm

RUN apt update -y
RUN apt install python3 -y
RUN apt install python3-pip -y
RUN apt install nginx -y

COPY app/templates ./templates
COPY app/main.py ./main.py
COPY app/utils.py ./utils.py
COPY app/sqlite3.db ./sqlite3.db
COPY requirements.txt ./requirements.txt

COPY default /etc/nginx/sites-available/default
COPY ssl/ /etc/ssl/

RUN python3 -m pip install -r requirements.txt
RUN python3 main.py

CMD service nginx start; uwsgi --socket 127.0.0.1:5050 --wsgi-file /app/main.py --callable app
EXPOSE 80 443