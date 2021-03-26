#!/usr/bin/env python3

from argparse import ArgumentParser
from pathlib import Path
import socket
import ssl
import urllib.parse
import urllib.request
import yaml


def set_defaults(config={}):
    if 'hostname' not in config:
        config['hostname'] = socket.getfqdn()
    return config


if __name__ == '__main__':
    script_dir = Path(__file__).resolve().parents[0]
    ap = ArgumentParser()
    ap.add_argument('--config', type=open,
                    default=str(script_dir / 'config.yml'),
                    help='YAML file with configuration options.')
    ap.add_argument('-n', '--principal', type=str, required=True,
                    help='Required: Username to use as principal')
    ap.add_argument('-r', '--requester', type=str, required=True,
                    help='Required: Entity ID of relying party')
    ap.add_argument('-f', '--format', type=str, nargs='?',
                    choices=['saml1', 'saml2', 'json'], default='saml2',
                    help='Output format (default: saml2)')
    args = ap.parse_args()
    config = yaml.safe_load(args.config)
    config = set_defaults(config)

    base = f"https://{config['hostname']}/idp/profile/admin/resolvertest"
    query = {
        'requester': args.requester,
        'principal': args.principal,
        args.format: True,
    }
    url = f'{base}?{urllib.parse.urlencode(query)}'

    cx = ssl.create_default_context()
    cx.verify_mode = ssl.CERT_OPTIONAL
    cx.check_hostname = False

    response = urllib.request.urlopen(url, context=cx)
    result = response.read().decode()
    print(result)
