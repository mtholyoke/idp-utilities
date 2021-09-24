#!/usr/bin/env python3

from argparse import ArgumentParser
from parsers import ShibbolethLog, WebserverLog


def help(args):
    argp.print_help()


def loops(args):
    log = WebserverLog()
    for filename in args.filename:
        log.load(filename)
    log.command_loops()


def service_providers(args):
    for party in args.relying_party: # allows for multiple party ID arguments
        kwargs = {
            'idpv': args.idp_version,
            'relying_party': party
        }
        log = ShibbolethLog(**kwargs)
        for filename in args.filename:
            log.load(filename)
        log.command_service_providers()


if __name__ == '__main__':
    argp = ArgumentParser()
    argp.set_defaults(command=help)
    subp = argp.add_subparsers(help=f'{__file__} {{command}} -h for more help')


    sp_p = subp.add_parser('sp', help='Service providers that used the IdP')
    sp_p.add_argument('-f', '--filename', type=str, nargs='*',
                      default=['/opt/shibboleth-idp/logs/idp-process.log'],
                      help='Log filename(s) to process, accepts wildcards')
    sp_p.add_argument('-i', '--idp-version', default=4,
                      help='IdP version')
    sp_p.add_argument('-r', '--relying-party', required=True, default=None, nargs='*',
                      help='Restrict to this relying party and list users')
    sp_p.set_defaults(command=service_providers)

    args = argp.parse_args()
    if args.command:
        args.command(args)
