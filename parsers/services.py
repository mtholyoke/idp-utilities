#!/usr/bin/env python3

from ._configfile import _ConfigFile


class ServicesConfig(_ConfigFile):
    ID_MAP = {
        'metadata': 'shibboleth.MetadataResolverResources',
    }

    def get_files(self, index):
        return self.stanzas[self.ID_MAP[index]]

    def parse_stanza(self, stanza):
        if stanza.tag != '{' + self.XMLNS['util'] + '}list':
            return []
        values = []
        for value in stanza:
            if value.tag != '{' + self.XMLNS['beans'] + '}value':
                continue
            text = value.text
            if '/system/' in text:
                continue
            values.append(self.make_path(text))
        return values
