#!/bin/sh
sudo apt-get install cmake zlib1g-dev libboost-system-dev libboost-program-options-dev libpthread-stubs0-dev libfuse-dev libudev-dev git 
mkdir console-client   
git clone https://github.com/pcloudcom/console-client.git ./console-client/  
cd ./console-client/pCloudCC/   
cd lib/pclsync/        
make clean    
make fs     
cd ../mbedtls/   
cmake .      
make clean     
make       
cd ../..      
cmake .    
make      
sudo make install     
ldconfig     
