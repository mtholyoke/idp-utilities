#!/usr/bin/env python3

from argparse import ArgumentParser
from parsers import ShibbolethLog
import os


def help(args):
    argp.print_help()


def scan(args):
    kwargs = {
        'principal': args.principal,
        'requester': args.requester,
        # 'sso': args.sso,
        'daily': args.daily,
        'output': args.output,
        # 'month': args.month,
    }
    log = ShibbolethLog(**kwargs)
    for filename in args.filename:
        log.load(filename)
    log.command_scan()


def main(args):
    if args.output:
        # If we specified an output directory, make sure it exists.
        output_dir = os.path.join(os.getcwd(), args.output)
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        args.output = output_dir
    scan(args)


if __name__ == '__main__':
    argp = ArgumentParser(
        description='''
            Scans Shib logs for instances of specified (or all) usernames
            logging into specified (or all) service providers, and returns
            counts as CSV of either totals or daily traffic.
        ''',
        epilog='''
            Specify neither -n nor -r to show all usernames and service
            providers. Specify both to see IP address and timestamp of
            all logins.''',
    )

    subject = argp.add_argument_group('Subjects to scan for')
    subject.add_argument(
        '-n', '--principal', default=None, nargs='+',
        help='Limit scan to the username(s) provided')
    subject.add_argument(
        '-r', '--requester', default=None, nargs='+',
        help='Limit scan to the service provider(s) provided')
    # subject.add_argument(
    #     '-s', '--sso', action='store_true',
    #     help='Determine if SSO was used within above limits')

    output = argp.add_argument_group('Output options')
    # TODO: -d needs exactly one of -n or -r.
    output.add_argument(
        '-d', '--daily', action='store_true',
        help='Provide daily usage as CSV for exactly one of -n or -r')
    output.add_argument(
        '-o', '--output', default=None, nargs='?',
        help='Create logs of results in this output directory')
    # output.add_argument(
    #     '-v', '--verbose', action='store_true',
    #     help='Provide verbose output')

    targets = argp.add_argument_group('Which log files to scan')
    # today = dt.date.today()
    # last_month = today.replace(day=1) - dt.timedelta(days=1)
    # month_default = last_month.strftime("%Y-%m")
    # targets.add_argument(
    #     '-m', '--month', default=None, const=month_default, nargs='?',
    #     help='Use all log files from a specific month')
    targets.add_argument(
        '-f', '--filename', type=str, nargs='*',
        default=['/opt/shibboleth-idp/logs/idp-process.log'],
        help='Log filename(s) to process, accepts wildcards')

    args = argp.parse_args()
    if args.daily:
        if ((args.principal and args.requester)
            or (not args.principal and not args.requester)):
            print('The -d/--daily option requires exactly one of -n/--principal or -r/--requester')
            exit(1)

    main(args)
