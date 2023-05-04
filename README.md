# picoTCP

---------------

PicoTCP-NG. License: GPLv2/v3 only.

This is a Free fork of PicoTCP, originally distributed by
[Altran.be](http://picotcp.altran.be).

---------------

picoTCP is a small-footprint, modular TCP/IP stack designed for embedded systems and the Internet of Things.

This code is released under the terms of GNU GPL v2 and GNU GPL v3.

Learn how to use picoTCP in your project by going through the **Getting Started guide** on our [GitHub wiki](https://github.com/virtualsquare/picotcp/wiki).

Contributions are welcome.


### Security considerations

-  ❗ Please see our list of [known vulnerabilities and security recommendations](docs/security.md) before use.

---------------

## Portability

By keeping interfaces simple, the porting effort to new platforms and OSses are very low. To give you an indication: porting to a new platform can be done in 3 days or less, a new OS in a single day and if you really go crazy, you can do an initial port in a single evening. Different platforms, mean different compilers, that’s why we continuously compile our stack with a bunch of them. The following list shows some of the currently supported platforms, device drivers and compilers.

###  PicoTCP has been used with

**Platforms picoTCP runs on**:
ARM Cortex-M series (ST Micro STM, NXP LPC, TI Stellaris, Freescale K64F),
ARM ARM9-series (ST Micro STR9),
Texas Instruments (MSP430),
Microchip (PIC24, PIC32),
Atmel (AVR 8bit),
Linux (User space (TUN/TAP), Kernel space),
Windows (User space (TAP))

**Network devices picoTCP has worked with**:
BCM43362 (IEEE 802.11), MRF24WG (IEEE 802.11), LPC Ethernet ENET/EMAC (IEEE 802.3), Stellaris Ethernet (IEEE 802.3), STM32 Ethernet (IEEE 802.3), Wiznet W5100 (IEEE 802.3), USB CDC-ECM (CDC1.2), PPP, Virtual drivers ( TUN/TAP, VDE, Libpcap)

**(RT)OSes picoTCP has been integrated into**:
No OS / Bare metal, FreeRTOS, mbed-RTOS, Frosted, linux / POSIX, MS DOS, MS Windows

**Libraries picoTCP has been integrated with**:
wolfSSL, mbedTLS, Mongoose RESTful library, MicroPython

**Compilers picoTCP compiles under**:
GCC, Clang, TCC, ARM-RCVT, IAR, XC-16, XC-32, MSP-GCC, AVR-GCC

---------------

## Configurable and modular design

Features are developed as modules in picoTCP, allowing you to pick the features you want in your application. This results in the smallest possible stack that remains compliant with the internet standards. The schematic below provides an overview of all implemented protocols.

![modular](https://s1.postimg.org/139xbnv7lb/image.png)

---------------

## Documentation

- [User Manual](docs/user_manual)
- [Wiki](https://github.com/virtualsquare/picotcp/wiki)


---------------

## Contributing

Contributors are very welcome. Report a bug, implement a new feature, submit a pull request.


