#!/usr/bin/env python3

from argparse import ArgumentParser
from parsers import MetadataResolverConfig, ServicesConfig
from pathlib import Path
import subprocess
import yaml


def set_defaults(config={}):
    if 'shibboleth-root' not in config:
        config['shibboleth-root'] = '/opt/shibboleth-idp'
    config['shibboleth-root'] = Path(config['shibboleth-root']).resolve()
    if 'properties' not in config:
        config['properties'] = {}
    if 'idp.home' not in config['properties']:
        config['properties']['idp.home'] = str(config['shibboleth-root'])
    if 'metadata-require' not in config:
        config['metadata-require'] = ['%{idp.home}/metadata/idp-metadata.xml']
    if 'xmllint' not in config:
        config['xmllint'] = '/usr/bin/xmllint'
    return config


def xmllint(config):
    if not config['xmllint']:
        return
    for dir in ['conf', 'metadata']:
        files = config['shibboleth-root'].glob(f'{dir}/**/*.xml')
        for file in files:
            result = subprocess.run([config['xmllint'], '--noout', file])
            result.check_returncode()


if __name__ == '__main__':
    script_dir = Path(__file__).resolve().parents[0]
    ap = ArgumentParser()
    ap.add_argument('--config', type=open,
                    default=str(script_dir / 'config.yml'),
                    help='YAML file with configuration options.')
    args = ap.parse_args()
    config = yaml.safe_load(args.config)
    config = set_defaults(config)

    xmllint(config)

    services_filename = str(config['shibboleth-root'] / 'conf/services.xml')
    services = ServicesConfig(config, [services_filename])

    metadata = MetadataResolverConfig(config, services.get_files('metadata'))
    metadata.check_files()
