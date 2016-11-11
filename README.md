# GDPDS Overview

The GDP Discovery Service (GDPDS) provides secure discovery and advertisement to clients using the Global Data Plane (GDP). GDPS servers advertise themselves on local networks, allowing clients to connect to them and advertise their capabilities to other clients connected to the GDP. This allows querying clients to identify clients which they have permission to interact with and which possess specific capabilities. GDPDS is designed to be used by lightweight and mobile clients while still providing the option of client authentication.

Please see "gdpds_overview.pdf" for a more detailed description of GDPDS.

# GDPDS Installation Instructions

### Clone GDPDS repo and create lib directory

```
cd gdp/lang/python/apps
mkdir git clone https://github.com/jordantipton/gdpds.git
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

# API Overview

### Setup a client's logs
#### This step is done once to register a client with GDPDS's global registry

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

```
python gdpds/client_setup.py
```