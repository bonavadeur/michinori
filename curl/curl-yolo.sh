#!/bin/bash
  
echo > curlall.txt

for ((i=1; i<=$1; i++))
do
        echo "---"$i
        curl -o /dev/null -w "@form.txt" yolo.default -F upload=@2_720p.jpg >> curlall.txt
        sleep 3
done