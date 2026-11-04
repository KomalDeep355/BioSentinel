FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Public demo defaults: live-model runs need DEMO_TOKEN, shared-state demo endpoints are off.
ENV BIOSENTINEL_PUBLIC=1
CMD ["sh", "-c", "uvicorn biosentinel.api:app --host 0.0.0.0 --port ${PORT:-8000}"]