FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y libpango-1.0-0 libcairo2 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# Eventlet worker is required for Flask-SocketIO websockets
CMD ["gunicorn", "-k", "eventlet", "-w", "1", "-b", "0.0.0.0:5000", "web_ui:app"]