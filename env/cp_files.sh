#!/bin/bash

ssh -o StrictHostKeyChecking=no -i ${1} ${2} hostname
ssh -o StrictHostKeyChecking=no -i ${1} ${2} rm -rf ~/ENV;
ssh -o StrictHostKeyChecking=no -i ${1} ${2} rm -rf ~/ktcp/;
ssh -o StrictHostKeyChecking=no -i ${1} ${2} mkdir -p ~/ENV;
scp -r -i ${1} `dirname $0`/ENV/* ${2}:ENV/
scp -r -i ${1} `dirname $0`/setup*sh ${2}:ENV/
scp -r -i ${1} `dirname $0`/params_${3}.txt ${2}:ENV/params.txt
ssh -o StrictHostKeyChecking=no -i ${1} ${2} ls ~/ENV

