#!/usr/bin/env python3

import os
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

# IdP metadata - should exist but not be in metadata-providers.xml
# TODO: command-line switch or local config for these?
idps = [
    'metadata/five-colleges/mtholyoke-login-idp-shibboleth.xml',
    'metadata/idpv4-test-2020-06-shibboleth.xml',
]
# XML namespaces we need multiple times:
ns = {
    'md': 'urn:mace:shibboleth:2.0:metadata',
    'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
}


def check_file(filename, files):
    ids = []
    tree = ET.parse(filename)
    root = tree.getroot()
    clear = True
    found = []
    for provider in root.findall('md:MetadataProvider', ns):
        # Confirm the id attribute is unique.
        id = provider.attrib.get('id')
        if id in ids:
            print(f'ERROR: found duplicate id "{id}"; aborting')
            sys.exit(1)
            continue
        ids.append(id)

        metadata_file = None
        optional = False
        xsi_type = provider.attrib.get(f'{{{ns["xsi"]}}}type')
        if xsi_type == 'FilesystemMetadataProvider':
            metadata_file = provider.attrib.get('metadataFile')
        elif xsi_type == 'FileBackedHTTPMetadataProvider':
            metadata_file = provider.attrib.get('backingFile')
            optional = True
        else:
            print(provider)
            continue

        if not metadata_file:
            print(f'ERROR: Can’t identify metadata file for {id}; aborting')
            sys.exit(1)
            continue

        # Make sure the specified file exists.
        if metadata_file in files:
            found.append(metadata_file)
            continue
        elif optional:
            # TODO: command-line switch to add verbose output here?
            continue
        print(f'Missing {metadata_file}')
        clear = False
    if clear:
        print(f'All SP metadata files in {filename} are present')
    return found


def main():
    home = str(Path(__file__).resolve().parents[1])
    os.chdir(home)
    print('-------------')

    # Get the list of all metadata files.
    files = []
    base = 'metadata'
    for dir, subdir_list, file_list in os.walk(base):
        for file in file_list:
            if file[-4:] != '.xml':
                continue
            dirfile = f'{dir}/{file}'
            if dirfile in idps:
                idps.remove(dirfile)
                continue
            files.append(f'%{{idp.home}}/{dirfile}')

    if idps:
        print(f'Missing IdP metadata:')
        for file in idps:
            print(f'  %{{idp.home}}/{file}')
    else:
        print('All expected IdP metadata files are present')

    # Check the metadata providers files:
    # TODO: command-line switch or local config for these?
    providers_files = [
        'conf/metadata-providers.xml',
        'conf/metadata-incommon.xml',
    ]
    for filename in providers_files:
        found = check_file(filename, files)
        files = [f for f in files if f not in found]

    if files:
        print('Extra metadata files:')
        for file in files:
            if file.endswith('.remote.xml') or file.endswith('.MDQ.xml'):
                continue
            print(f'  {file}')


if __name__ == '__main__':
    main()
