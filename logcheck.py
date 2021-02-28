#!/usr/bin/env python3

from argparse import ArgumentParser
from parsers import ShibbolethLog, TomcatLog


def help(args):
    argp.print_help()


def loops(args):
    log = TomcatLog()
    for filename in args.filename:
        log.load(filename)
    log.command_loops()


def service_providers(args):
    kwargs = {
        'idpv': args.idp_version,
        'relying_party': args.relying_party
    }
    log = ShibbolethLog(**kwargs)
    for filename in args.filename:
        log.load(filename)
    log.command_service_providers()


if __name__ == '__main__':
    argp = ArgumentParser()
    argp.set_defaults(command=help)
    subp = argp.add_subparsers(help=f'{__file__} {{command}} -h for more help')

    loop_p = subp.add_parser('loop', help='Scan Tomcat log for looping')
    loop_p.add_argument('-f', '--filename', type=str, nargs='*',
                        default=['/var/log/tomcat9/access.log'],
                        help='Log filename(s) to process, accepts wildcards')
    loop_p.set_defaults(command=loops)

    sp_p = subp.add_parser('sp', help='Service providers that used the IdP')
    sp_p.add_argument('-f', '--filename', type=str, nargs='*',
                      default=['/opt/shibboleth-idp/logs/idp-process.log'],
                      help='Log filename(s) to process, accepts wildcards')
    sp_p.add_argument('-i', '--idp-version', default=4,
                      help='IdP version')
    sp_p.add_argument('-r', '--relying-party', default=None,
                      help='Restrict to this relying party and list users')
    sp_p.set_defaults(command=service_providers)

    args = argp.parse_args()
    if args.command:
        args.command(args)
