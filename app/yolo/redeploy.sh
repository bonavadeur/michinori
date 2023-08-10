#!/bin/bash

kubectl delete -f service.yaml
sleep 3
kubectl delete pod --all --force
sleep 3
kubectl apply -f service.yaml
