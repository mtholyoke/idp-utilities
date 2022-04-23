#!/usr/bin/env python3

from argparse import ArgumentParser
from pathlib import Path
import json
import socket
import ssl
import urllib.parse
import urllib.request
import yaml


def format_easy(input=""):
    parsed = json.loads(input)
    attrib_list = parsed['attributes']
    attrib_dict = {}
    max_length = 0
    for attrib in attrib_list:
        if len(attrib['values']) == 1:
            attrib_dict[attrib['name']] = attrib['values'][0]
        else:
            attrib_dict[attrib['name']] = attrib['values']
        if len(attrib['name']) > max_length:
            max_length = len(attrib['name'])
    output = []
    for key in sorted(attrib_dict):
        output.append(f'{key:{max_length}} = {attrib_dict[key]}')
    return "\n".join(output)

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
                    choices=['saml1', 'saml2', 'json', 'easy'],
                    default='saml2',
                    help='Output format (default: saml2)')
    args = ap.parse_args()
    config = yaml.safe_load(args.config)
    config = set_defaults(config)

    base = f"https://{config['hostname']}/idp/profile/admin/resolvertest"
    format = args.format if args.format != 'easy' else 'json'
    query = {
        'requester': args.requester,
        'principal': args.principal,
        format: True,
    }
    url = f'{base}?{urllib.parse.urlencode(query)}'

    cx = ssl.create_default_context()
    cx.verify_mode = ssl.CERT_OPTIONAL
    cx.check_hostname = False

    response = urllib.request.urlopen(url, context=cx)
    result = response.read().decode()
    if args.format == 'easy':
        result = format_easy(result)
    print(result)
