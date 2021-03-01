#!/usr/bin/env python3

from argparse import ArgumentParser
from parsers import MetadataResolverConfig, ServicesConfig
from pathlib import Path
import yaml


if __name__ == '__main__':
    script_dir = Path(__file__).resolve().parents[0]
    ap = ArgumentParser()
    ap.add_argument('--config', type=open,
                    default=str(script_dir / 'config.yml'),
                    help='YAML file with configuration options.')
    args = ap.parse_args()
    config = yaml.safe_load(args.config)

    config['shibboleth_root'] = Path(config['shibboleth_root']).resolve()
    if 'properties' not in config:
        config['properties'] = {}
    if 'idp.home' not in config['properties']:
        config['properties']['idp.home'] = str(config['shibboleth_root'])
    services_filename = str(config['shibboleth_root'] / 'conf/services.xml')
    services = ServicesConfig(config, services_filename)

    resolver_files = services.stanzas['shibboleth.MetadataResolverResources']
    metadata = MetadataResolverConfig(config, resolver_files)
    metadata.check_files()
