# Monitor module for a Sandbox
## Introduction
This project is about "Building a sandbox for supporing malware analysis". In this topic, I will focus on building a small part of the monitor module of sandbox. This module is used to log the input parameter before and after some target APIs is called, including the return result as well
## Repository Structure
The monitor module source code and executable is place in `Monitor` folder

The testing program source code and executable for testing the functionality of the monitor module is place in `Testing_Program` folder
## Building monitor from Source
If you want to build the client from source code, open the project in the InfoDumping folder in Visual Studio, choose Release, x64, and build it again. This project was developed using Visual Studio 2022 version 17.6.2.
If any error occurs related to the 'Detour lib', you may need to redefined the path to the library which is place in the `detour_lib` folder. Open the `properties` window in the Visual Studio. 
- choose C\C++ -> General -> Additional Include Directories -> Add the path to `detour_lib\x86 and x64` folder
- choose Linker -> General -> Additional Library Directories -> Add the path to `detour_lib\x86 and x64` folder
