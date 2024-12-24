#!/bin/bash

apt update -y && apt upgrade -y && apt install -y sudo
sudo apt-get update -y && sudo apt-get upgrade -y
sudo apt-get install -y \
  python3 python3-pip python3-dev python3.10 python3.10-venv build-essential cmake wget sqlite3

if [ ! -d "venv_crocgpt" ]; then
  python3.10 -m venv venv_crocgpt
else
  echo "Virtual environment already exists."
fi

source venv_autoppia/bin/activate
python3.10 -m pip install --upgrade pip
pip install -r requirements.txt