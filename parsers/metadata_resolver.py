#!/usr/bin/env python3

from ._configfile import _ConfigFile


class MetadataResolverConfig(_ConfigFile):
    """
    This is an aggregate of all the metadata resolver config files
    specified in `conf/services.xml`, in the order they are listed.
    """

    # Compare the contents of the metadata directory with the list
    # of files expected by the metadata resolver config files, plus
    # anything required by `config.yml`.
    def check_files(self):
        filenames = self.load_files()
        missing = {}

        # Check for everything required by config.
        required = self.config['metadata-require']
        if isinstance(required, str):
            required = [required]
        for i, idp in enumerate(required, start=1):
            check = self.make_path(idp)
            if check in filenames:
                filenames.remove(check)
            else:
                missing[f'(metadata-require #{i})'] = {'provider': check}

        # Check for everything required by MetadataProvider stanzas.
        for id, stanza in self.stanzas.items():
            if stanza['filename'] in filenames:
                filenames.remove(stanza['filename'])
            elif stanza['required']:
                missing[id] = stanza

        # Report results.
        if missing:
            for id, s in missing.items():
                print(f'ERROR: Missing {id} metadata file {s["filename"]}')
        else:
            print('All required metadata files are present')
        for filename in self.config['metadata-ignore']:
            check = self.make_path(filename)
            if check in filenames:
                filenames.remove(check)
        if filenames:
            print('Extra metadata files:')
            for filename in filenames:
                print(f'  - {filename}')

    # Returns a list of strings which are fully qualified filenames
    # from the IdP’s `metadata/` directory and all subdirectories.
    def load_files(self):
        metadata_dir = self.config['shibboleth-root'] / 'metadata'
        return [str(f) for f in metadata_dir.glob('**/*.xml')]

    # Returns a dict summarizing the requirement: what filename
    # we expect and whether we can allow it to be missing.
    def parse_stanza(self, stanza):
        if stanza.tag != self.xmlns('md', 'MetadataProvider'):
            return None
        id = stanza.attrib.get('id')
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
