FROM python:3.10-slim

# Install dependencies for mysqlclient and pkg-config
RUN apt-get update && \
    apt-get install -y default-libmysqlclient-dev gcc pkg-config && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements.txt
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY . .

# Command to run the application
CMD ["python", "app.py"]
