FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y suricata && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ml /app/ml
COPY privacy /app/privacy
COPY detector_service.py /app/detector_service.py
COPY rule_engine.py /app/rule_engine.py
COPY merge_alerts.py /app/merge_alerts.py
CMD ["python", "/app/detector_service.py"]
