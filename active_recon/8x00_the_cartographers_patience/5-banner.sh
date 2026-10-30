#!/bin/bash
openssl s_client -connect 10.10.10.30:4650 -starttls smtp -servername mail.berent.lab -showcerts
