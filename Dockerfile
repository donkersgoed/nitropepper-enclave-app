FROM amazonlinux

RUN yum install python3 gcc net-tools -y

WORKDIR /app

COPY libnsm.so ./
COPY requirements.txt ./

RUN pip3 install -r requirements.txt

COPY main.py ./
COPY kms.py ./
COPY traffic-forwarder.py ./
COPY run.sh ./

RUN chmod +x run.sh
CMD ["/app/run.sh"]
