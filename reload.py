#!/usr/bin/env python3

from argparse import ArgumentParser
from pathlib import Path
import socket
import ssl
import urllib.parse
import urllib.request
import yaml


def set_defaults(config):
    if config is None:
        config = {}
    if 'hostname' not in config:
        config['hostname'] = socket.getfqdn()
    return config


if __name__ == '__main__':
    script_dir = Path(__file__).resolve().parents[0]
    ap = ArgumentParser()
    ap.add_argument('--config', type=open,
                    default=str(script_dir / 'config.yml'),
                    help='YAML file with configuration options.')
    ap.add_argument('-a', '--attribute-resolver', action='append_const',
                    const='AttributeResolverService', dest='services',
                    help='Load changes from conf/attribute-resolver.xml')
    ap.add_argument('-f', '--attribute-filter', action='append_const',
                    const='AttributeFilterService', dest='services',
                    help='Load changes from conf/attribute-filter.xml')
    ap.add_argument('-m', '--metadata-resolver', action='append_const',
                    const='MetadataResolverService', dest='services',
                    help='Load changes from conf/metadata-providers.xml')
    ap.add_argument('-r', '--relying-party-resolver', action='append_const',
                    const='RelyingPartyResolverService', dest='services',
                    help='Load changes from conf/relying-party.xml')
    args = ap.parse_args()
    if args.services is None:
        ap.print_help()
        exit(1)

    config = yaml.safe_load(args.config)
    config = set_defaults(config)

    base = f"https://{config['hostname']}/idp/profile/admin/reload-service"
    for service in args.services:
        query = {'id': f"shibboleth.{service}"}
        url = f'{base}?{urllib.parse.urlencode(query)}'

        cx = ssl.create_default_context()
        cx.verify_mode = ssl.CERT_OPTIONAL
        cx.check_hostname = False

        response = urllib.request.urlopen(url, context=cx)
        result = response.read().decode()
        print(result)
