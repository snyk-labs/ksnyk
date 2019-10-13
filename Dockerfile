FROM python:alpine

RUN pip3 install pysnyk click kubernetes 

COPY . /app

ENTRYPOINT ["python3", "/app/ksnyk.py"]
CMD ["--help"]
