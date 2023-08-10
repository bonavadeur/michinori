from torch import hub
model = hub.load('ultralytics/yolov5', 'yolov5n', pretrained=True)
