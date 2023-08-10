FROM ultralytics/yolov5:latest-cpu
RUN mkdir detection
COPY requirements.txt detection

RUN export LC_CTYPE=en_US.UTF-8
RUN python3 -m pip install --upgrade pip wheel
RUN pip3 install Flask
RUN pip3 install -r detection/requirements.txt

RUN mkdir detection/darknet
COPY darknet detection/darknet
WORKDIR detection

RUN apt-get install build-essential -y
RUN make -C darknet

COPY setup.py .
COPY yolov5n.pt .
COPY yolo_detection.py .
COPY run.sh .

# RUN pwd && ls
RUN python3 setup.py
# RUN python3 setup.py

EXPOSE 8080
CMD ["sh","./run.sh"]
# RUN pwd && ls