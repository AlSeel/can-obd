# can-obd
Implementation of  ISO 15031-5 as Linux Module

============================================================================

CREDITS

This linux module was derived from repository https://github.com/hartkopp/can-isotp.git
with Oliver Hartkopp's permission. Also the build 
enviroment was adapted to project spicific needs.

DOWNLOAD and BUILD

1. Download repository

      git clone https://github.com/AlSeel/can-obd.git

2. Build OBD kernel module

   Ensure dependencies are installed.  For Debian (or Ubuntu):

      sudo apt-get install build-essential linux-headers-$(uname -r)

   To build:

      make

   To install (optional):

      sudo make modules_install

   To build sample application:

      make obdsend


3. When the PF_CAN core module is loaded ('modprobe can') the OBD module
   can be loaded into the kernel with

       insmod /lib/modules/$(uname -r)/extra/net/can/can-obd.ko

   When the can-obd.ko module has been installed into the Linux Kernels
   modules directory (e.g. with 'make modules_install') the module should
   load automatically when opening a CAN_OBD socket.
   
   Obd interface macros are delivered with "obd.h". 

----------------------------------------------------------------------------

Readme file for OBD CAN transport protocol for protocol family CAN

* Features:
* - no check of sequence number is perfomed
* - sending of more than one obd request not possible (prohibited 
*   according to ISO 15031-5)
* - possible timing delay for receiving obd responses. Obd response is 
*   considered as completly received after P2CAN or P2CANEXT is elapsed.   
* - only can IDs allowed in ISO 15765-4 are send

  1 What is OBD for CAN

  2 Tools and Examples
    2.1 obdsend - send OBD messages from stdin to CAN


1 What is OBD for CAN
------------------------

  OBD Transport Protocol is used as an exchange of diagnostic messages
  between external test equipment and OBD enabled ECUs.

2 Tools and Examples
--------------------

  2.1 obdsend - send OBD messages from stdin to CAN

	Usage:     obdsend <canid#data> <interface> <P2CAN:opt> <P2CANEXT:opt>

	Optitions:
	    <canid#data>   (Canid and data separated by '#'.
                            OBD allowes 11 byte identifiers:  
                                 0x7DF (functionally address), 0x7E0-0x7E7
                            OBD allowes 29 byte identifiers:  
                                 0x18DB33F1 (functionally address), 0x18DA00F1-0x18DAFFF1
                            Data bytes are max 7 bytes as hex.
                            Data bytes are separated by '.'.
	    <interface>    (device interface)
	    <CANP2:opt>    (Optional parameter. Timeout in ns for obd respose.
                            Omit it for default 50ms.)
	    <CANP2EXT:opt> (Optional parameter. Timeout in sec for obd respose
                            after negative response. Omit it for default 5s.)

	Example 1: ./obdsend 0x7DF#01.01.20.40  can0
	Example 2: ./obdsend 0x18DB33F1#01.01.20.40  can0
	Example 3: ./obdsend 0x7E0#01.01.20.40.80 can0 100
	Example 4: ./obdsend 0x18DA00F1#01.01.20.40.80 can0 100 7


        ./obdsend returns obd response on stdout. 
        Structure of response message: 
               [ <first canid:4 bytes> <data lenght:2 bytes> <data> 
                 <next canid:4 bytes> <data lenght:2 bytes> <data> 
                 <next canid:4 bytes> <data lenght:2 bytes> <data> 
                 ...
                 <last canid:4 bytes> <data lenght:2 bytes> <data> ]

        Example response: 0 0 7 e8      0 6     41 00 fe 21 01 34
                         | can id | data length|       data       |
                
        In case of an error (bus error, driver error) in the field
        canid the bit CAN_ERR_FLAG is set.
        If the error message was generated from can driver the complete
        error message is forwarded to application.  
        Example response: 20 xx xx xx    00 6       11 34 56 ef 21
                         |  can id    | data length|  error msg    |

        Protocol errors are signaled via error messages also.
        If no obd response is received within specific time 
        20 00 00 00 00 00 error message (bit CAN_ERR_FLAG set) is generated.

