#! /bin/bash

cargo build --release && sudo systemctl restart web_server.service 
