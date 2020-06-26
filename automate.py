#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import binascii
import logging
import argparse
import json
import subprocess
import time
import sys

logger = logging.getLogger(__name__)
#log_level = logging.ERROR
#log_level = logging.WARNING
log_level = logging.INFO
#log_level = logging.DEBUG

logging.basicConfig(format='%(asctime)s %(message)s', level=log_level)

hci_interface_down = 'sudo hciconfig hci0 down'
hci_interface_up = 'sudo hciconfig hci0 up'
hci_interface_piscan = 'sudo hciconfig hci0 piscan'
hci_interface_auth = 'sudo hciconfig hci0 auth'

ble_scan_command = 'sudo timeout 10 hcitool lescan'
ble_connect_command = 'sudo hcitool lecc '

def shell_command_without_result(command, wait_time, terminate_flag):
    process = subprocess.Popen(command, universal_newlines=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(wait_time)
    if terminate_flag:
        process.terminate()

def shell_command_with_result(command, wait_time, terminate_flag):
    process = subprocess.Popen(command, universal_newlines=True, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    retcode = process.wait()
    time.sleep(wait_time)
    if terminate_flag:
        process.terminate()
    text = process.stdout.read()
    print(text)
    if len(text) > 0:
        return text
    
def manage_hci(reset, setup):
    sleep_time = 0.2
    if reset == True:
        shell_command_without_result(hci_interface_down, sleep_time, True)
        time.sleep(sleep_time)
        shell_command_without_result(hci_interface_up, sleep_time, True)
    if setup == True:
        shell_command_without_result(hci_interface_piscan, sleep_time, True)
        time.sleep(sleep_time)
        shell_command_without_result(hci_interface_auth, sleep_time, True)
    
def process_mac_addresses(mac_add_list):
    for mac in mac_add_list:
        logger.info("\t" + str(mac))
    manage_hci(True, True)
    ble_scan_result = shell_command_with_result(ble_scan_command, 10, False)
    logger.info(ble_scan_result)

def main():
    parser = argparse.ArgumentParser(description='Help display')
    
    requiredNamed = parser.add_argument_group('required named arguments')
    requiredNamed.add_argument("-l", "--list", help="List of MAC Address to change BLE Tag mode parameters(view example files).", required=True)
    
    optionnalNamed = parser.add_argument_group('optional named arguments')
    optionnalNamed.add_argument("-o", "--output", help="Output log file.", required=False)

    args = parser.parse_args()
    
    # Log into a file
    if args.output is not None :
        # Check if files already exists
        if os.path.isfile(args.output):
            print('Error: log file already exists')
            exit(-1)
        el = (args.output).split('.')
        el.insert(-1, 'success')
        if os.path.isfile( ".".join(el) ):
            print('Error: success file output already exists')
            exit(-1)
        el = (args.output).split('.')
        el.insert(-1, 'error')
        if os.path.isfile( ".".join(el) ):
            print('Error: error file output already exists')
            exit(-1)
        root = logging.getLogger('')
        fh = logging.FileHandler(args.output)
        fh.setLevel(log_level)
        fh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
        root.addHandler(fh)
    
    logger.info("Starting BLE Tag mode parameter updates")
    logger.info("")
    
    mac_add_list = []
     
    if args.list.find(".json") > 0:
        logger.info("Parse file in JSON mode")
        with open(args.list,'r') as json_file:
            data = json.load(json_file)
            for t in data:
                mac_add_list.append( t['Barcode'] )
    elif args.list.find(".txt") > 0:
        logger.info("Parse file in TXT mode")
        with open(args.list,'r') as txt_file:
            lines = txt_file.readlines()
            for l in lines:
                mac_add_list.append( l.rstrip() )
    else:
        logger.info("Error: {} is not in supported list format file. Only JSON and TXT are supported.".format(str(args.list)))
        exit(-1)
    
    logger.info("Found {} MAC addresses in {}".format(str(len(mac_add_list)),str(args.list)))

    process_mac_addresses(mac_add_list)

    logger.info("BLE Tag pair report: total={}".format(str(len(mac_add_list))))
    logger.info("Full process is finished.")
    exit(0)

#tcpdump_capture_unlimited_byte_packets = 'tcpdump -i {e} -s0 -w {c}'.format(e=eth_interface, c=cap_pcap_file)
#shell_result = shell_command_with_result(tcpdump_display_all_packets, 0, False)
#shell_command_without_result(tcpdump_capture_unlimited_byte_packets, capture_time, True)

if __name__ == '__main__':
    main()
