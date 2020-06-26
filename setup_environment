#!/bin/bash -e
#
# Setup the environment for using pybluez

if [ -z "$AG" ]; then
    AG="sudo apt-get -qqy --no-install-recommends"
fi

echo AG is $AG

user=$(whoami)
echo "Current user: $user"

$AG update || true

#bluetooth dependancies
$AG install bluetooth libbluetooth-dev libboost-python-dev libboost-thread-dev
$AG install libglib2.0-dev pkg-config python3-dev libboost-all-dev
$AG install libdbus-1-dev libusb-dev libudev-dev libical-dev libreadline-dev

#python 3.8 dependancies
$AG install build-essential tk-dev libncurses5-dev libncursesw5-dev
$AG install libreadline6-dev libdb5.3-dev libgdbm-dev libsqlite3-dev
$AG install libssl-dev libbz2-dev libexpat1-dev liblzma-dev zlib1g-dev
$AG install libffi-dev tar wget vim

#python 3.8 install
wget https://www.python.org/ftp/python/3.8.0/Python-3.8.0.tgz
sudo tar zxf Python-3.8.0.tgz
cd Python-3.8.0
sudo ./configure --enable-optimizations
sudo make -j 4
sudo make altinstall
cd ..
python3.8 -Vx
echo "alias python=/usr/local/bin/python3.8" >> ~/.bashrc
source ~/.bashrc
python -V

sudo python3.8 -m pip install --upgrade pip
sudo python3.8 -m pip install -U setuptools
sudo python3.8 -m pip install pyinstaller
sudo python3.8 -m pip install wheel
sudo python3.8 -m pip install pygattlib
sudo python3.8 -m pip install pexpect

#gattlib setup
#rm -rf gattlib*
#pip3 download gattlib
#gatt_path=$(ls | grep ^gattlib)
#echo $gatt_path

#tar xvzf ./$gatt_path
#gatt_path=${gatt_path%.tar.gz}
#echo $gatt_path

#cd $gatt_path
#sed -ie 's/boost_python-py34/boost_python-py35/' setup.py
#sudo pip3 install .
#cd ..

sudo python3.8 -m pip install -vvv pybluez
sudo python3.8 -m pip install -vvv pybluez[ble]

#update to bluez-5.54 
wget http://www.kernel.org/pub/linux/bluetooth/bluez-5.54.tar.xz
tar xvf bluez-5.54.tar.xz
cd bluez-5.54/
sudo apt-get update
sudo ./configure
sudo make
sudo make install
cd ..
sudo systemctl daemon-reload
sudo systemctl stop bluetooth
sudo systemctl start bluetooth
sudo systemctl status bluetooth

