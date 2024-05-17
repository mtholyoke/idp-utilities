#!/usr/bin/env python3

from argparse import ArgumentParser
from parsers import WebserverLog

# Load each log to scan
def scan(args):
    log = WebserverLog()
    for filename in args.filename:
        log.load(filename)
        scanLog(log)

# Scan a specific log
def scanLog(log):
    log.command_loops()

    # Create a dictionary to track devices by IP address and user agent
    devices_by_ip = {}

    for id in log.sequences:
        for sequence in log.sequences[id]:
            ip_addr = sequence.events[0].ip_addr
            user_agent = sequence.events[0].browser  # User agent as the identifier

            # Combine IP address and user agent to uniquely identify the device
            device_identifier = f'{ip_addr}:{user_agent}'

            # Check if the IP address is already in the dictionary
            if ip_addr in devices_by_ip:
                # If the device is not in the list for this IP address, add it
                if device_identifier not in devices_by_ip[ip_addr]:
                    devices_by_ip[ip_addr].append(device_identifier)
                    if len(devices_by_ip[ip_addr]) > 1:
                        print(f'Multiple devices detected from {ip_addr}: {", ".join(devices_by_ip[ip_addr])}\n')  
            else:
                # Initialize the list for this IP address with the first device
                devices_by_ip[ip_addr] = [device_identifier]

            # Continue with loop detection logic using WebserverSequence
            loops = sequence.detect_loops()
            for timecode, loop_events in loops.items():
                print(
                    f'Loop detected from {ip_addr:15s} {user_agent:40s} {timecode} - {len(loop_events):4d} - {loop_events[0]}\n')

if __name__ == "__main__":
    argp = ArgumentParser(
        epilog='')
    argp.add_argument('-f', '--filename', type=str, nargs='*',
                      default=['access.2021-02-01.log'],
                      help='Log filename(s) to process, accepts wildcards')

    args = argp.parse_args()
    scan(args)
