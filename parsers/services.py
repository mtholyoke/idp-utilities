#!/usr/bin/env python3

from ._configfile import _ConfigFile


class ServicesConfig(_ConfigFile):
    """
    This is a representation of `conf/services.xml`, which the IdP
    uses to identify the names of other config files that it loads.
    """

    # Short forms of stanza ids for convenience elsewhere.
    ID_MAP = {
        'attr-filter': 'shibboleth.AttributeFilterResources',
        'attr-resolver': 'shibboleth.AttributeResolverResources',
        'metadata': 'shibboleth.MetadataResolverResources',
        'nameid': 'shibboleth.NameIdentifierGenerationResources',
    }

    def get_files(self, index):
        return self.stanzas[self.ID_MAP[index]]

    # Returns a list of the contents of <value> elements.
    def parse_stanza(self, stanza):
        if stanza.tag != self.xmlns('util', 'list'):
            return []
        values = []
        for value in stanza:
            if value.tag != self.xmlns('beans', 'value'):
                continue
            text = value.text
            if '/system/' in text:
                continue
            values.append(self.make_path(text))
        return values
