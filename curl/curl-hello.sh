#!/bin/bash
  
echo "" > curlall.txt

for ((i=1; i<=$1; i++))
do
        echo "---"$i
        curl -w "@form.txt" hello.default >> curlall.txt
        sleep 10
done