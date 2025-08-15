# Experimental container; OS detection requires capabilities.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap git build-essential libffi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create runtime dirs
RUN mkdir -p data logs content/ansible-lockdown

EXPOSE 8000
ENV BIND=0.0.0.0 PORT=8000

CMD ["bash", "run.sh"]
