#!/usr/bin/env python3

from argparse import ArgumentParser
from parsers import ShibbolethLog
import datetime as dt

today = dt.date.today()
first = today.replace(day=1)
last_month = first - dt.timedelta(days=1)
month_default = last_month.strftime("%Y-%m")

def help(args):
    argp.print_help()

def scan(args):
    kwargs = {
        'principal': args.principal,
        'requester': args.requester,
        'month' : args.month,
        'output' : args.output,
        'single_sign_on': args.single_sign_on
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
    #I don't think that atm this is the right nargs, revisit. 
    argp.add_argument('-m', '--month', default=None, const=month_default, nargs='?',
                      help='Restrict to this month and list service providers and usernames')
    argp.add_argument('-o', '--output', default='output', nargs='?',
                      help='Create logs of results in this output directory.')
    argp.add_argument('-s', '--single_sign_on', default=None, const=True, nargs='?', 
                      help='Looks information on single sign on usage.')

    args = argp.parse_args()
    scan(args)
