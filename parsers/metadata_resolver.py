#!/usr/bin/env python3

from ._configfile import _ConfigFile


class MetadataResolverConfig(_ConfigFile):
    def parse_stanza(self, stanza):
        if stanza.tag != self.xmlns('md', 'MetadataProvider'):
            return None
        id = stanza.attrib.get('id')
        provider = None
        optional = False
        xsi_type = stanza.attrib.get(self.xmlns('xsi', 'type'))
        if xsi_type == 'FilesystemMetadataProvider':
            provider = stanza.attrib.get('metadataFile')
        elif xsi_type == 'FileBackedHTTPMetadataProvider':
            provider = stanza.attrib.get('backingFile')
        else:
            raise ValueError(f'Can’t parse stanza with id {id}')
        if not provider:
            raise ValueError(f'Can’t find filename in stanza with id {id}')
        return {
            'xsi_type': xsi_type,
            'provider': self.make_path(provider),
            'optional': optional,
        }

    def _old_check_file(self, filename):
        # ids = []
        # tree = ET.parse(filename)
        # root = tree.getroot()
        clear = True
        found = []
        for provider in root.findall('md:MetadataProvider', self.XMLNS):
            # Confirm the id attribute is unique.
            # id = provider.attrib.get('id')
            # if id in ids:
            #     print(f'ERROR: found duplicate id "{id}"; aborting')
            #     sys.exit(1)
            #     continue
            # ids.append(id)

            # metadata_file = None
            # optional = False
            # xsi_type = provider.attrib.get(f'{{{self.XMLNS["xsi"]}}}type')
            # if xsi_type == 'FilesystemMetadataProvider':
            #     metadata_file = provider.attrib.get('metadataFile')
            # elif xsi_type == 'FileBackedHTTPMetadataProvider':
            #     metadata_file = provider.attrib.get('backingFile')
            #     optional = True
            # else:
            #     print(provider)
            #     continue

            # if not metadata_file:
            #     print(f'ERROR: Can’t identify metadata file for {id}; aborting')
            #     sys.exit(1)
            #     continue

            # Make sure the specified file exists.
            if metadata_file in self.files:
                self.files.remove(metadata_file)
                continue
            elif optional:
                # TODO: command-line switch to add verbose output here?
                continue
            print(f'Missing {metadata_file}')
            clear = False
        if clear:
            print(f'All SP metadata files in {filename} are present')

    def _old_check_files(self):
        for filename in self.filenames:
            self.check_file(filename)
        if self.files:
            print('Extra metadata files:')
            for file in self.files:
                if file.endswith('.remote.xml') or file.endswith('.MDQ.xml'):
                    continue
                print(f'  {file}')

    def _old_load_metadata_files(self, config):
        metadata_dir = config['shibboleth_root'] / 'metadata'
        for globfile in metadata_dir.glob('**/*.xml'):
            filename = str(globfile.relative_to(config['shibboleth_root']))
            if filename in self.idps:
                self.idps.remove(filename)
                continue
            self.files.append('%{idp.home}/' + filename)
        if self.idps:
            print('Missing IdP metadata:')
            for file in idps:
                print('%{idp.home}/' + file)
        else:
            print('All expected IdP metadata files are present')
