#!/usr/bin/env python3

from argparse import ArgumentParser
from parsers import ShibbolethLog


def help(args):
    argp.print_help()


def scan(args):
    kwargs = {
        'principal': args.principal,
        'requester': args.requester
    }
    log = ShibbolethLog(**kwargs)
    for filename in args.filename:
        log.load(filename)
    log.command_scan()


if __name__ == '__main__':
    argp = ArgumentParser(
        epilog='Specify neither -n nor -r to show all service providers. Specify both to see IP address and timestamp of logins.')
    argp.add_argument('-f', '--filename', type=str, nargs='*',
                      default=['/opt/shibboleth-idp/logs/idp-process.log'],
                      help='Log filename(s) to process, accepts wildcards')
    argp.add_argument('-n', '--principal', default=None, nargs='+',
                      help='Restrict to this username and list service providers')
    argp.add_argument('-r', '--requester', default=None, nargs='+',
                      help='Restrict to this service provider and list usernames')

    args = argp.parse_args()
    scan(args)
