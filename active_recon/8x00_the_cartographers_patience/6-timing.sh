#!/bin/bash
nmap -sS -T3 --scan-delay 1s --max-rate 1 -p8443 10.10.10.20
