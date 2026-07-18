# Sample (intentionally vulnerable) app image for the demo
FROM python:3.9

# outdated base image, known CVEs in python:3.9 slim/base layers

RUN apt-get update && apt-get install -y curl

WORKDIR /app
COPY requirements.txt .

# vulnerable/outdated pinned versions on purpose
RUN pip install -r requirements.txt

COPY . .

# runs as root, no USER directive - security smell
EXPOSE 5000
CMD ["python", "app.py"]
