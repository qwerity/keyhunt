# cuda-keyhunt-pvk

# Build
There is needed to install following packages to be able to compile

## Ubuntu 24.04
- nvidia-cuda-toolkit (12.0.1)
- libtbb-dev
- libboost-dev-all

## Windows x64
- Visual Studio 2019 Community
- [NVidia Cuda Toolkit 12.6.1](https://developer.download.nvidia.com/compute/cuda/12.6.1/local_installers/cuda_12.6.1_560.94_windows.exe)
- Boost 1.86
  - [Download archive](https://github.com/boostorg/boost/releases/download/boost-1.86.0/boost-1.86.0-cmake.7z)
  - Unpack to `C:/boost/boost-1.86.0/` -> BOOST_ROOT
  - Open Powershell in **BOOST_ROOT**
    - `./bootstrap.bat`
    - `./b2 -j14 toolset=msvc-14.2 threading=multi address-model=64 link=static runtime-link=static variant=release --with-system --with-log --with-iostreams stage`

# Build Win x64
- Open Terminal in project directory
- `cmake -G "Visual Studio 16 2019" -A x64 -DCMAKE_CUDA_ARCHITECTURES=86 -S . -B build`
- `cmake --build .\build\ --config=Release -j 14 --target cuda-keyhunt-pvk`
- If all good you can find the binary in `{project directory}/bin` folder
- Copy the config.json to bin folder and 


# Convert Hex string Hash160 target file to binary
- Build `convert_hash160_to_binary` target
- `convert_hash160_to_binary hex_str_hash160_targetx.txt`
- This will generate `hex_str_hash160_targetx.txt.bin` binary file
- Replace in config file the targets list with binary files