#!/bin/sh

# Start the API server in the background
cd /usr/src/app/api
HOST=0.0.0.0 PORT=4000 LOG_LEVEL=debug npm start &

# Start the client server
cd /usr/src/app/client
CONFIG_FILE=./src/env/authly.js npm start