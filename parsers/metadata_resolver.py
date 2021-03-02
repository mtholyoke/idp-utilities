#!/usr/bin/env python3

from ._configfile import _ConfigFile


class MetadataResolverConfig(_ConfigFile):
    def check_files(self):
        filenames = self.load_files()
        missing = {}

        # Check to make sure IdP metadata is present.
        idp_metadata = self.config['idp_metadata']
        if isinstance(idp_metadata, str):
            idp_metadata = [idp_metadata]
        for i, idp in enumerate(idp_metadata, start=1):
            check = self.make_path(idp)
            if check in filenames:
                filenames.remove(check)
            else:
                missing[f'(config.yml idp #{i})'] = {'provider': check}

        # Check for everything required by MetadataProvider stanzas.
        for id, stanza in self.stanzas.items():
            if stanza['provider'] in filenames:
                filenames.remove(stanza['provider'])
            elif stanza['required']:
                missing[id] = stanza

        # Report results.
        if missing:
            for id, s in missing.items():
                print(f'ERROR: Missing {id} metadata file {s["provider"]}')
        else:
            print('All required metadata files are present')
        if filenames:
            print('Extra metadata files:')
            for filename in filenames:
                print(f'  - {filename}')

    def load_files(self):
        metadata_dir = self.config['shibboleth_root'] / 'metadata'
        return [str(f) for f in metadata_dir.glob('**/*.xml')]

    def parse_stanza(self, stanza):
        if stanza.tag != self.xmlns('md', 'MetadataProvider'):
            return None
        id = stanza.attrib.get('id')
        xsi_type = stanza.attrib.get(self.xmlns('xsi', 'type'))
        provider = None
        required = True
        if xsi_type == 'FilesystemMetadataProvider':
            provider = stanza.attrib.get('metadataFile')
        elif xsi_type == 'FileBackedHTTPMetadataProvider':
            provider = stanza.attrib.get('backingFile')
            required = False
        else:
            raise ValueError(f'Can’t parse stanza with id {id}')
        if not provider:
            raise ValueError(f'Can’t find filename in stanza with id {id}')
        return {
            'xsi_type': xsi_type,
            'provider': self.make_path(provider),
            'required': required,
        }
