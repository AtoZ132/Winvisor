 # Winvisor
Winvisor is a simple hypervisor designed to run an app in an already running system with ept hooking features. Its (being) written in C as a Windows kernel driver utilizing Intel VT-X.
It's still WIP

# Goal 
- The projects' goal of this project is to dive both into kernel development and virtualization technology.
- The technical goal is to act as a research infrastructure for runtime debugging. The current milestone is ept hooking and several features. There are currently no additional goals besides this (maybe in the future).

# Notes
The project is not yet finished and doesnt contain all the specified above functionality.

# Credit and Learning Material
Most of the material I used to learn about the technology and the development of this project 
is based on:
- [Sina Karvandi](https://twitter.com/Intel80x86) and her amazing blog - [Hypervisor From Scratch](https://rayanfam.com/topics/hypervisor-from-scratch-part-1/)
- [Alex Ionescu](https://twitter.com/aionescu) and his [SimpleVisor](https://github.com/ionescu007/SimpleVisor)
- [Satoshi Tanda](@standa_t) and his [HyperPlatform](https://tandasat.github.io/HyperPlatform/userdocument/)
- and of course [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
