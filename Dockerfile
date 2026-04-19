FROM python:3.12-slim

# Chrome + ChromeDriver + tcpdump + libpcap (for scapy)
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "run.py"]
