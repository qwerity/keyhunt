# cuda-keyhunt-pvk

## How to compile for all GPU support
- `cmake -G "Visual Studio 16 2019" -A x64 -DCMAKE_CUDA_ARCHITECTURES="all" -S . -B build`
- `cmake --build .\build\ --config=Release -j 14 --target cuda-keyhunt-pvk`

## How to compile for concrete GPUs support
- `cmake -G "Visual Studio 16 2019" -A x64 -DCMAKE_CUDA_ARCHITECTURES=86 -S . -B build`
- `cmake --build .\build\ --config=Release -j 14 --target gpu_info`
- Run GPU info to get the existing GPUs capability
  - `.\bin\gpu_info.exe`
  - Output example:
```
ID:     0
Name:   NVIDIA GeForce RTX 3080 Ti
Minor: 8, Major: 6
Capability: 86
warpSize: 32
Memory: 12287
multiProcessorCount: 80
maxThreadsPerMultiProcessor: 1536
globalL1CacheSupported: 1
localL1CacheSupported: 1
l2CacheSize: 6291456
persistingL2CacheMaxSize: 4325376

ID:     1
Name:   NVIDIA GeForce RTX 2060 SUPER
Minor: 7, Major: 5
Capability: 75
warpSize: 32
Memory: 8191
multiProcessorCount: 34
maxThreadsPerMultiProcessor: 1024
globalL1CacheSupported: 1
localL1CacheSupported: 1
l2CacheSize: 4194304
persistingL2CacheMaxSize: 0
```
  - So now we have Capability for each of device, and ready compile `cuda-keyhunt-pvk` for concrete devices
    - `cmake -G "Visual Studio 16 2019" -A x64 -DCMAKE_CUDA_ARCHITECTURES="75;86" -S . -B build`
    - `cmake --build .\build\ --config=Release -j 14 --target cuda-keyhunt-pvk`

## Build
There is needed to install following packages to be able to compile

### Ubuntu 24.04
- nvidia-cuda-toolkit (12.0.1)
- libtbb-dev
- libboost-dev-all

### Windows x64
- Visual Studio 2019/2022 Community 
- [NVidia Cuda Toolkit 12.6.1](https://developer.download.nvidia.com/compute/cuda/12.6.1/local_installers/cuda_12.6.1_560.94_windows.exe)
- Boost 1.86
  - [Download archive](https://github.com/boostorg/boost/releases/download/boost-1.86.0/boost-1.86.0-cmake.7z)
  - Unpack to `C:/boost/boost-1.86.0/` -> BOOST_ROOT
  - Open Powershell in **BOOST_ROOT**
    - `./bootstrap.bat`
    - If there is existing previous builds please remove `bin.v2` and `stage` directories
    - `./b2 -j14 toolset=msvc-14.2,msvc-14.3 cxxflags="/std:c++20" threading=multi address-model=64 link=static runtime-link=static variant=debug,release --with-headers --with-system --with-log --with-iostreams --with-regex stage`
- Openssl 3.4.0 // no need to do this, already added to the project
  - Open VS 2019 development prompt 
  - `perl Configure VC-WIN64A -march=native enable-asm no-shared no-docs no-tests --prefix=C:\Users\ksh\workspace\openssl-3.4.0\build --openssldir=C:\Users\ksh\workspace\openssl-3.4.0\build`
  - `set CL=/MP && nmake install` // for multi-thread compilation

## Build Win x64
- Open Terminal in project directory
- `cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_CUDA_ARCHITECTURES=86 -S . -B build`
- `cmake --build .\build\ --config=Release -j 14 --target cuda-keyhunt-pvk`
- If all good you can find the binary in `{project directory}/bin` folder
- Copy the config.json to bin folder and 


## Convert Hex string Hash160 target file to binary
- Build `convert_hash160_to_binary` target
- `convert_hash160_to_binary hex_str_hash160_targetx.txt`
- This will generate `hex_str_hash160_targetx.txt.bin` binary file
- Replace in config file the targets list with binary files


## use vast ai 
- create instance with custom template
- wget https://storage.googleapis.com/data_btc_r/startup.sh && chmod +x ./startup.sh