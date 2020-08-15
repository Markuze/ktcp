#!/bin/bash

echo "enable ip forwarding"
sysctl -w net.ipv4.ip_forward=1
sysctl net.ipv4.ip_forward