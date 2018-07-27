	
FROM rsmmr/hilti:latest
LABEL maintainer="Justyna Chromik <j.j.chromik@utwente.nl>"
LABEL description="This docker extends the rsmmr:hilti docker with some network tools."

ENV DATAPATH /data
ENV PYTHONPATH=$PYTHONPATH:/usr/local/lib/python

RUN apt-get -y update && apt-get -y  install net-tools tcpreplay tcpdump
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y tshark

WORKDIR $DATAPATH