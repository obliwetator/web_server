#! /bin/bash

cargo build --release && sudo systemctl restart sakiot-web-server.service 
