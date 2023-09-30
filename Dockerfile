FROM python:3.9-slim-buster

RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    wget\
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /home
COPY nmap-7.92.tar.bz2 .
RUN tar -xf nmap-7.92.tar.bz2
WORKDIR /home/nmap-7.92
RUN #chmod a+x configure
RUN ./configure --prefix=/usr
RUN make
RUN make install

WORKDIR /usr/share/nmap/scripts/
COPY vulners.nse .
RUN nmap --script-updatedb

RUN mkdir /code
WORKDIR /code

COPY requirements.txt .
RUN python3.9 -m pip install --no-cache-dir --upgrade \
    pip \
    setuptools \
    wheel
RUN python3.9 -m pip install --no-cache-dir \
    -r requirements.txt
COPY . .

CMD ["python3.9", "main.py", "--mode=PROD"]