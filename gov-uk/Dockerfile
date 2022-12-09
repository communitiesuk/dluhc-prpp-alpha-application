FROM python:3.8
WORKDIR /python-docker
COPY . .
RUN pip install --upgrade pip
RUN pip3 install -r requirements.txt
RUN apt-get update; apt-get install curl -y
RUN ./build.sh
EXPOSE 8000
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]

