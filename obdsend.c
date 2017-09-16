/*
 * obdsend.c - example application for can-obd.ko
 *
 * This programm has a demonstration purpose of usage the can-obd
 * module. The can-obd was derived from can-isotp implementing
 * ISO 15765-2 CAN protocol publiced by Oliver Hartkopp
 * (https://github.com/hartkopp/can-isotp.git). Therefore
 * following copyright are applied.
 *
 * Copyright (c) 2008 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 *
 */

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <linux/can.h>
#include "obd.h"


void print_usage(char * prog){
	printf("                                                                        \n");
	printf("Usage:     obdsend <canid#data> <interface> <P2CA:opt> <P2CANEXT:opt>   \n");
	printf("                                                                        \n");
	printf("Optitions:                                                              \n");
	printf("    <canid#data>   (Canid and data separated by '#'.                    \n");
        printf("                    OBD valid 11 byte identifiers:                      \n");
        printf("                    0x7DF (functionally address), 0x7E0-0x7E7 )         \n");
        printf("                    OBD valid 29 byte identifiers:                      \n");
        printf("                    0x18DB33F1 (functionally address),                  \n");
        printf("                    0x18DA00F1-0x18DAFFF1                               \n");
        printf("                    Data bytes are max 7 bytes as hex.                  \n");
        printf("                    Data bytes are separated by '.'.                    \n");
	printf("    <interface>    (device interface)                                   \n");
	printf("    <CANP2:opt>    (Optional parameter. Timeout in ns for obd respose.  \n");
        printf("                    Omit it for default 50ms.)                          \n");
	printf("    <CANP2EXT:opt> (Optional parameter. Timeout in sec for obd respose  \n");
        printf("                    after negative response. Omit it for default 5s.)   \n");
	printf("                                                                        \n");
	printf("Example 1: ./obdsend 0x7DF#01.01.20.40  can0                            \n");
	printf("Example 2: ./obdsend 0x18DB33F1#01.01.20.40  can0                       \n");
	printf("Example 3: ./obdsend 0x7E0#01.01.20.40.80 can0 100                      \n");
	printf("Example 4: ./obdsend 0x18DA00F1#01.01.20.40.80 can0 100 7               \n");
	printf("                                                                        \n");
	printf("./obdsend returns the obd response on stdout.                           \n");
        printf("obd response format:                                                    \n");
	printf("   [ <first canid: 4 byte, big endianess> <data length: 2 byte, big endianess> <data>\n");
	printf("     <next canid: 4 byte, big endianess>  <data length: 2 byte, big endianess> <data>\n");
	printf("     <next canid: 4 byte, big endianess>  <data length: 2 byte, big endianess> <data>\n");
        printf("     ...                                                                             \n");
	printf("     <last canid: 4 byte, big endianess>  <data length: 2 byte, big endianess> <data> ]\n");
	printf("                                                                        \n");
	printf("                                                                        \n");
        printf("In case of a fault an error message is send to application. Error       \n");
        printf("message has the same structure as standard message but in the canid     \n");
        printf("field bit CAN_ERR_FLAG is set.If no response is received within         \n");
        printf("specified time an error msg is generated also.                          \n");
        printf("Example: 20 00 00 00 00 00 (error message of length 0)                  \n");
        printf("Example: 20 xx xx xx 00 04 12 13 14 15 (error message of length 4)      \n");
}


int main(int argc, char **argv)
{
    struct sockaddr_can addr;
    unsigned char buf[MAX_RESPONSE_BUFFER];
    char *string;
    int retval = 0;
    unsigned long p2can = 0;
    long p2canext = 0;
    int len = 0;
    int i;
    canid_t tx;
    unsigned long long timediff;
    int s;
    socklen_t optlen;


    if (argc < 3 || argc > 5) {
	print_usage(argv[0]);
	exit(1);
    }

    strcpy((char*)buf,argv[1]);
    string = strtok((char*)buf,"#. ");

    //get can id
    if(string != NULL){
	  tx = (canid_t)strtoul(string,NULL,16);
          if(tx > 0x7EF){
		tx |= CAN_EFF_FLAG;
          }
    }

    //get data bytes
    len = 0;
    string = strtok(NULL,"#. ");
    while(string != NULL && len < 8){
	  buf[len] = strtol(string,NULL,16);
          len++;
	  string = strtok(NULL,"#. ");
    }

    //get CANP2
    if (argc == 4){
    	p2can = strtol(argv[3],NULL,10);
    }
    //get CANP2EXT
    if (argc == 5){
    	p2canext = strtol(argv[4],NULL,10);
    }

    //create obd socket
    if ((s = socket(PF_CAN, SOCK_DGRAM, CAN_OBD)) < 0) {
	printf("socket error\n");
	exit(1);
    }

    addr.can_family = AF_CAN;
    addr.can_ifindex = if_nametoindex(argv[2]);
    addr.can_addr.tp.tx_id = tx;


    //bind
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	printf("bind error\n");
	close(s);
	exit(1);
    }

    //change CANP2 if was requested
    if(p2can > 0){
    	if (setsockopt(s, SOL_CAN_OBD, CAN_OBD_RX_P2_CAN, &p2can, sizeof(unsigned long)) < 0){
	 	printf("error setting sockopt p2 can\n");
		exit(1);
    	}
    }

    //change CANP2EXT if was requested
    if(p2canext > 0){
    	if(setsockopt(s, SOL_CAN_OBD, CAN_OBD_RX_P2_CAN_EXT, &p2canext, sizeof(long)) < 0){
		printf("error setting sockopt p2 can ext\n");
	 	exit(1);
    	}
    }

    //this block has only demostration purpose. The CANID was set while bind().
    //Via setsockopt() we can change CANID before sending a obd request.
    if (setsockopt(s, SOL_CAN_OBD, CAN_OBD_TX_CANID, &tx, sizeof(canid_t)) < 0){
	printf("error setting sockopt TX ID\n");
	exit(1);
    }

    //len contains number of bytes to be send. Max 7 byte.
    retval = write(s,buf, len);
    if (retval < 0) {
	printf("write error\n");
	exit(1);
    }

    if (retval != len)
	printf("wrote only %d from %d byte\n", retval,len);


    /*obd response format:
	[ <first canid: 4 byte, big endianess> <data length: 2 byte, big endianess> <data>
	  <next canid: 4 byte, big endianess>  <data length: 2 byte, big endianess> <data>
	  <next canid: 4 byte, big endianess>  <data length: 2 byte, big endianess> <data>
          ...
	  <last canid: 4 byte, big endianess>  <data length: 2 byte, big endianess> <data> ]

     In case of a fault an error message is send to application. Error message has the same
     structure as standard message but in the canid field bit CAN_ERR_FLAG is set.
     If no response is received within specified time an error msg is generated also.
     Example: 20 00 00 00 00 00 (error message of length 0)
     Example: 20 xx xx xx 00 04 12 13 14 15 (error message of length 4)
    */
    retval = read(s,buf,MAX_RESPONSE_BUFFER);
    if(retval>0){
	if (buf[0] & 0x20){
		printf("no obd response or can error\n");
	}
	printf("obd response: [");
	for(i=0;i<retval;i++){
		printf(" %hhx",buf[i]);
	}
	printf("]\n");
    }

    //after received obd response we can read time elapsed between obd request send and received response.
    optlen = sizeof(unsigned long long);
    if ((getsockopt(s, SOL_CAN_OBD, CAN_OBD_TIMEDIFF, &timediff, &optlen) < 0) && (optlen == sizeof(unsigned long long))){
	printf("error geting timediff\n");
	exit(1);
    }
    printf("request <=> response: %llu msec\n",timediff/1000000);

    return 0;

}


