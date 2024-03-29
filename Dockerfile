FROM python:3.11-alpine
RUN apk add --no-cache --update sudo openjdk13 apache-ant build-base bash busybox-extras libffi-dev tcpdump libpcap-dev iptables curl libpq-dev libc6-compat npm
RUN pip3 install "scapy[basic]" pcapy-ng impacket sqlalchemy psycopg2 jsons pyyaml==5.3.1
RUN npm install -g pyright
RUN curl -o /usr/bin/wait-for-it https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh && chmod +x /usr/bin/wait-for-it
COPY . /code
WORKDIR /code/Adapter
RUN pyright --warnings
WORKDIR /code
RUN ant -f Mapper/build.xml dist
WORKDIR /root
CMD iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP && sleep 30 && wait-for-it implementation:44344 -s -- wait-for-it database:5432 -s -- python3 -u /code/Adapter/Adapter.py
