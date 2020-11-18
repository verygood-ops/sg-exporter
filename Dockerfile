FROM python:3.8-buster
COPY requirements.txt /requirements.txt
RUN pip3 install -r /requirements.txt
RUN mkdir /app
COPY sg_exporter /app/sg_exporter
ENV PYTHONPATH=/app
ENTRYPOINT ["python3", "-m", "sg_exporter"]
