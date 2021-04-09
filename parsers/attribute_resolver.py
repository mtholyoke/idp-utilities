#!/usr/bin/env python3

from ._configfile import _ConfigFile


class AttributeResolverConfig(_ConfigFile):
    """
    This is a representation of `conf/attribute-resolver.xml`, in order
    to identify which attributes are available for release.
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

    # The attribute name from an <AttributeDefinition> element is its id;
    # this returns a string containing its type, or None for other elements.
    def parse_stanza(self, stanza):
        if stanza.tag != self.xmlns('resolver', 'AttributeDefinition'):
            return None
        return stanza.attrib.get(self.xmlns('xsi', 'type'))
