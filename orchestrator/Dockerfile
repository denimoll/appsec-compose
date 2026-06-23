FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Reports land in the shared volume; config is mounted read-only at runtime.
ENTRYPOINT ["python", "-u", "main.py"]
