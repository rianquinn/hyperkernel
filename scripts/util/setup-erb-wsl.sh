#!/bin/bash

sudo apt update
sudo apt-get install -y make cmake gcc g++ python autoconf bison flex \
    texinfo help2man gawk libtool libtool-bin libncurses5-dev libelf-dev \
    libssl-dev

# Download a new cmake
pushd $HOME
wget https://cmake.org/files/v3.12/cmake-3.12.1-Linux-x86_64.tar.gz
tar xzf cmake-3.12.1-Linux-x86_64.tar.gz
echo 'export PATH="$HOME/cmake-3.12.1-Linux-x86_64/bin:$PATH"' >> $HOME/.bashrc
popd
