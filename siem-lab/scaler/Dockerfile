FROM python:3.12-alpine
WORKDIR /app
RUN pip install --no-cache-dir docker==7.1.0 redis==5.0.1
COPY scaler/main.py .
CMD ["python", "-u", "main.py"]
