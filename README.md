# GDPDS Overview

The GDP Discovery Service (GDPDS) provides secure discovery and advertisement to clients using the Global Data Plane (GDP). GDPS servers advertise themselves on local networks, allowing clients to connect to them and advertise their capabilities to other clients connected to the GDP. This allows querying clients to identify clients which they have permission to interact with and which possess specific capabilities. GDPDS is designed to be used by lightweight and mobile clients while still providing the option of client authentication.

Please see the GDPDS Overview pdf for a more detailed description of GDPDS.

# GDPDS Installation Instructions

### Clone GDPDS repo and create lib directory

```
cd gdp/lang/python/apps
git clone https://github.com/jordantipton/gdpds.git
cd gdpds
mkdir lib
cd lib
```

### Follow instructions to install opendht

```
# Install GnuTLS 3, Readline and Nettle, Ubuntu 14.10+
sudo apt-get install libncurses5-dev libreadline-dev nettle-dev libgnutls-dev
# Install GnuTLS 3, Readline and Nettle, Ubuntu 14.04
# sudo apt-get install libncurses5-dev libreadline-dev nettle-dev libgnutls28-dev

# Install python binding dependencies
sudo apt-get install cython3 python3-dev python3-setuptools

# Build and install msgpack-c 1.3
sudo apt-get install build-essential cmake
wget https://github.com/msgpack/msgpack-c/releases/download/cpp-1.3.0/msgpack-1.3.0.tar.gz
tar -xzf msgpack-1.3.0.tar.gz
cd msgpack-1.3.0 && mkdir build && cd build
cmake -DMSGPACK_CXX11=ON -DMSGPACK_BUILD_EXAMPLES=OFF -DCMAKE_INSTALL_PREFIX=/usr ..
make -j
sudo make install

# clone the repo
cd ../..
git clone https://github.com/savoirfairelinux/opendht.git

# build and install
cd opendht
mkdir build && cd build
cmake -DOPENDHT_PYTHON=ON -DCMAKE_INSTALL_PREFIX=/usr ..
make -j
sudo make install
```

### Install python dependencies

```
sudo apt-get install mysql-server
sudo apt-get install python-dbus
sudo apt-get install python-gobject-2-dev
sudo apt-get install python-avahi
sudo apt-get install python-mysqldb
sudo apt-get install python-crypto
sudo apt-get install libssl-dev
sudo pip install requests
sudo pip install flask
sudo pip install flask_restful
sudo python3 -m pip install flask
sudo python3 -m pip install flask_restful
```

### Create MySQL user for the local_server and/or global_registry and grant permissions
Note: the password below is used as an example and should be changed
''' 
mysql -u root -p
CREATE USER 'gdp_discovery'@'localhost' IDENTIFIED BY 'gdp_disc438';
GRANT ALL PRIVILEGES ON * . * TO 'gdp_discovery'@'localhost';
'''


# API Overview

### Run Global Registry
#### This is only necessary if there is no other global registry to bootstrap a local server to

Ensure that port 80 (for HTTP requests) and port 4222 (input bootstrap port) are open.
These ports can optionally be changed to a different port using command line options.

Run the global registry server
```
sudo python gdpds/global_registry.py -u <registry MySQL user> -p <registry MySQL pw> 
```

### Run Local Discovery Server
#### One of these should be run on each local subnet through which devices will connect
Run local server, specifying the global registry (or other local server) as a bootstrap node
```
python gdpds/local_server.py -u <local MySQL user> -p <local MySQL pw> -b <global bootstrap ip>:<port>
```

### Setup the info log for a client class and register it
#### This step is done once to register a type of client with GDPDS's global registry

Create a registry configuration file of the following form:
```
CAPABILITIES:
<capability 1>
<capability 2>
...
<capability n>
PERMISSIONS:
<permission 1>
<permission 2>
...
<permission n>
```

Create a new info log and then run client_setup to write the configuration file 
to the info log
```
python gdpds/client_setup.py <info_log> <info_log signing-key-file> <registration_config-file>
```
Register the newly created info log with the global discovery server (using Postman, for example)
```
PUT http://<global registry address>:<global registry port>/rest/v1/deviceclasses
form data:
info_log: <info log>
```

### Run client module
#### A python thread should call client.advertise in a client or gateway (on the client's behalf)
```
import gdpds

gdpds.client.advertise(guid=<guid>, info_log=<info_log>, output_log=<output_log>, input_log=<input_log>)
```