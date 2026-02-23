FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir "fastapi[standard]"
COPY main.py ./
COPY static ./static
CMD ["fastapi", "run", "main.py"]
