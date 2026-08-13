#!/bin/bash

IP_TARGET=$1

if [[ -z "$IP_TARGET" ]]; then
    exit 1
fi

echo iptables -A INPUT -s "$IP_TARGET" -j DROP