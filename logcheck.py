#!/usr/bin/env python3

from argparse import ArgumentParser
from parsers import ShibbolethLog, WebserverLog
# import numpy as np


def help(args):
    argp.print_help()


def loops(args):
    log = WebserverLog()
    for filename in args.filename:
        log.load(filename)
    log.command_loops()


def service_providers(args):

    # -r is not specified
    if args.relying_party == None:
        # neither -r nor -n specified
        if args.name == None:
            print("You must specify either -n or -r or both.")
        # -n specified
        else:
            relying_parties(args)
        return 0

    for party in args.relying_party: # allows for multiple party ID arguments
        kwargs = {
            'idpv': args.idp_version,
            'relying_party': party
        }
        log = ShibbolethLog(**kwargs)
        for filename in args.filename:
            log.load(filename)
        log.command_service_providers()

    # both -n and -r switches specified
    if not args.name == None:
        args.relying_party = None
        relying_parties(args)


# works similarly to service_providers: for a given username, print out each relying_party accessed by it
def relying_parties(args):

     for name in args.name:
            kwargs = {
                'idpv': args.idp_version,
                'name': name,
            }

            kwargs['relying_party'] = args.relying_party   # we'll get an error if there's an empty list

            log = ShibbolethLog(**kwargs)
            for filename in args.filename:
                log.load(filename)
            log.command_relying_parties()

if __name__ == '__main__':
    argp = ArgumentParser()
    argp.set_defaults(command=help)
    # subp = argp.add_subparsers(help=f'{__file__} {{command}} -h for more help')


    # sp_p = subp.add_parser('sp', help='Service providers that used the IdP')
    argp.add_argument('-f', '--filename', type=str, nargs='*',
                       default=['/opt/shibboleth-idp/logs/idp-process.log'],
                      help='Log filename(s) to process, accepts wildcards')
    argp.add_argument('-i', '--idp-version', default=4,
                      help='IdP version')
    argp.add_argument('-r', '--relying-party', default=None, nargs='*',
                      help='Restrict to this relying party and list users')
    argp.add_argument('-n', '--name', default=None, nargs='*',
                      help='Restrict to this entity id and list relying parties') # takes a username and returns the relying party IDs (with counts)
    argp.set_defaults(command=service_providers)

    args = argp.parse_args()
    if args.command:
        args.command(args)
