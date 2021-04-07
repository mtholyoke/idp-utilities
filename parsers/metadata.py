#!/usr/bin/env python3

from ._configfile import _ConfigFile
import cryptography
import xml.etree.ElementTree as ET


class MetadataConfig(_ConfigFile):
    """
    This is an individual metadata file.
    """

    # Overrides _ConfigFile.load_stanzas because we want to work with
    # the root element as a single stanza.
    def load_stanzas(self, filename):
        tree = ET.parse(filename)
        root = tree.getroot()
        id = root.attrib.get('entityID')
        try:
            stanza = self.parse_stanza(root)
        except ValueError as ve:
            raise RuntimeError(f'Can’t load {filename}') from ve
        else:
            if stanza:
                self.stanzas[id] = stanza

    # Returns a dict of parsed contents.
    def parse_stanza(self, stanza):
        if stanza.tag != self.xmlns('md', 'EntityDescriptor'):
            print(f'Unknown tag: {stanza.tag}')
            return None
        return {
            'tree': stanza,
        }
        # id = stanza.attrib.get('id')
        # char = re.search(r'([^\w-])', id)
        # if char:
        #     raise ValueError(f'Invalid character "{char.group(1)}" in {id}')
        # filename = None
        # required = True
        # xsi_type = stanza.attrib.get(self.xmlns('xsi', 'type'))
        # if xsi_type == 'FilesystemMetadataProvider':
        #     filename = stanza.attrib.get('metadataFile')
        # elif xsi_type == 'FileBackedHTTPMetadataProvider':
        #     filename = stanza.attrib.get('backingFile')
        #     required = False
        # else:
        #     raise ValueError(f'Can’t parse stanza with id {id}')
        # if not filename:
        #     raise ValueError(f'Can’t find filename in stanza with id {id}')
        # return {
        #     'filename': self.make_path(filename),
        #     'required': required,
        # }
