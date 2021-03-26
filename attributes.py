#!/usr/bin/env python3

from argparse import ArgumentParser
import socket
import ssl
import urllib.parse
import urllib.request
import yaml


if __name__ == '__main__':
    ap = ArgumentParser()
    ap.add_argument('-n', '--principal', type=str, required=True,
                    help='Required: Username to use as principal')
    ap.add_argument('-r', '--requester', type=str, required=True,
                    help='Required: Entity ID of relying party')
    ap.add_argument('-f', '--format', type=str, nargs='?',
                    choices=['saml1', 'saml2', 'json'], default='saml2',
                    help='Output format (default: saml2)')
    args = ap.parse_args()

    base = f'https://{socket.getfqdn()}/idp/profile/admin/resolvertest'
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
