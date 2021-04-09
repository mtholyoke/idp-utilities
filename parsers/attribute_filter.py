#!/usr/bin/env python3

from ._configfile import _ConfigFile


class AttributeFilterConfig(_ConfigFile):
    """
    This is a representation of `conf/attribute-filter.xml`, in order
    to identify which attributes are being released.
    """
    # Inherited variables:
    #     PATH_SUB = re.compile(...)
    #     XMLNS = {...}
    # Inherited methods:
    #     __init__(self, config, filenames)
    #     load_stanzas(self, filename)
    #     make_path(self, text)
    #     translate_config(self)
    #     xmlns(self, ns, item)

    # Inverts stanza => attribute list mapping for queries.
    def get_released(self):
        release = {}
        for id, attrs in self.stanzas.items():
            for attr in attrs:
                if attr not in release:
                    release[attr] = []
                release[attr].append(id)
        return release

    # Returns a list of the attributes in <AttributeFilterPolicy> elements.
    def parse_stanza(self, stanza):
        if stanza.tag != self.xmlns('afp', 'AttributeFilterPolicy'):
            return []
        values = []
        for value in stanza:
            if value.tag != self.xmlns('afp', 'AttributeRule'):
                continue
            values.append(value.attrib.get('attributeID'))
        return values
