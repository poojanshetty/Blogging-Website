FROM python:3.9

RUN pip install --upgrade pip \
    && pip install pipenv

WORKDIR /app

COPY Pipfile Pipfile.lock /app/

RUN pipenv install --system --deploy

COPY . /app

RUN chmod +x /app/main.py
EXPOSE 5001
RUN ls -l /app/main.py
CMD ["python3", "/app/main.py"]
