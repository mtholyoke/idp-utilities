#!/usr/bin/env python3

from . import MetadataConfig
from ._configfile import _ConfigFile
import cryptography
import re


class MetadataResolverConfig(_ConfigFile):
    """
    This is an aggregate of all the metadata resolver config files
    specified in `conf/services.xml`, in the order they are listed.
    """

    # Compare the contents of the metadata directory with the list
    # of files expected by the metadata resolver config files, plus
    # anything required by `config.yml`.
    def check_files(self):
        files = self.load_files()
        missing = {}

        # Check expiration of metadata.
        if self.config['check_expiry']:
            for filename, metadata in files.items():
                if filename in self.config['metadata-ignore']:
                    continue
                expiry = metadata.check_expiry()
                if (expiry):
                    print(filename)
                    for note in expiry:
                        print(f'- {note}')

        # Check for everything required by config.
        for i, check in enumerate(self.config['metadata-require'], start=1):
            if check in files:
                del files[check]
            else:
                missing[f'(metadata-require #{i})'] = {'filename': check}

        # Check for everything required by MetadataProvider stanzas.
        for id, stanza in self.stanzas.items():
            if stanza['filename'] in files:
                del files[stanza['filename']]
            elif stanza['required']:
                missing[id] = stanza

        # Report results.
        if missing:
            for id, s in missing.items():
                print(f'ERROR: Missing {id} metadata file {s["filename"]}')
        else:
            print('All required metadata files are present')
        for check in self.config['metadata-ignore']:
            if check in files:
                del files[check]
        if files:
            print('Extra metadata files:')
            for filename, _ in files.items():
                print(f'  - {filename}')

    # Returns a list of strings which are fully qualified filenames
    # from the IdP’s `metadata/` directory and all subdirectories.
    def load_files(self):
        metadata_dir = self.config['shibboleth-root'] / 'metadata'
        files = {}
        for filename in metadata_dir.glob('**/*.xml'):
            files[str(filename)] = MetadataConfig(self.config, [filename])
        return files

    # Returns a dict summarizing the requirement: what filename
    # we expect and whether we can allow it to be missing.
    def parse_stanza(self, stanza):
        if stanza.tag != self.xmlns('metadata', 'MetadataProvider'):
            return None
        id = stanza.attrib.get('id')
        char = re.search(r'([^\w-])', id)
        if char:
            raise ValueError(f'Invalid character "{char.group(1)}" in {id}')
        filename = None
        required = True
        xsi_type = stanza.attrib.get(self.xmlns('xsi', 'type'))
        if xsi_type == 'FilesystemMetadataProvider':
            filename = stanza.attrib.get('metadataFile')
        elif xsi_type == 'FileBackedHTTPMetadataProvider':
            filename = stanza.attrib.get('backingFile')
            required = False
        else:
            raise ValueError(f'Can’t parse stanza with id {id}')
        if not filename:
            raise ValueError(f'Can’t find filename in stanza with id {id}')
        return {
            'filename': self.make_path(filename),
            'required': required,
        }
