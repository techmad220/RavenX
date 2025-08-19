
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["bash", "-lc", "ravenx --targets configs/targets.txt --attest-authorized yes --output out && uvicorn ravenx.api.main:app --host 0.0.0.0 --port 8080"]
