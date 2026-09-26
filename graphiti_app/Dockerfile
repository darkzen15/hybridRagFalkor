FROM python:3.11-slim
WORKDIR /app

# Install git so pip can clone Github repositories
RUN apt-get update && apt-get install -y git

COPY requirements.txt .
# Force pip to upgrade all packages to bypass Docker cache
RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY . .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]