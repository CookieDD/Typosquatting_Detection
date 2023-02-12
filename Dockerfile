FROM public.ecr.aws/lts/ubuntu:20.04_stable

COPY  wrapper_script.sh .

COPY english.dict .

COPY abused_tlds.dict .

COPY requirements.txt .

COPY aws_config.yaml .

COPY typosquatting_detection.py .

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update

RUN apt install -y python3

RUN apt install -y python3-pip

RUN apt install -y firefox-geckodriver

RUN pip3 install -r requirements.txt

RUN ["chmod", "+x", "./wrapper_script.sh"]

CMD ./wrapper_script.sh
