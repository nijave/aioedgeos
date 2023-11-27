FROM python:3.12

WORKDIR /app
COPY requirements.txt /app/
RUN python3 -m pip install --no-cache -U pip wheel setuptools \
  && pip install --no-cache -r /app/requirements.txt

COPY influx.py /app/

ENTRYPOINT ["python3"]
CMD ["/app/influx.py"]
