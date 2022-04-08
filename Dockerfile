FROM python:3.10-slim

RUN mkdir "app"

COPY requirements.txt /app

COPY . /app

WORKDIR /app

RUN pip install psycopg2-binary

RUN pip install -r requirements.txt

CMD ["uvicorn", "main:app", "--host=0.0.0.0"]
