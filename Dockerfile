FROM python:3.10-slim

RUN mkdir "app"

COPY ./src /app/src

COPY ./requirements.txt /app

WORKDIR /app

RUN pip install -r requirements.txt

RUN pip install psycopg2-binary

CMD ["uvicorn", "src.main:app", "--port=8080", "--host=0.0.0.0"]
