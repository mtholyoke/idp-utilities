#!/usr/bin/env python3

from ._configfile import _ConfigFile


class AttributeResolverConfig(_ConfigFile):
    """
    This is a representation of `conf/attribute-resolver.xml`, in order
    to identify which attributes are available for release.
    """

    # The attribute name from an <AttributeDefinition> element is its id;
    # this returns a string containing its type, or None for other elements.
    def parse_stanza(self, stanza):
        if stanza.tag != self.xmlns('resolver', 'AttributeDefinition'):
            return None
        return stanza.attrib.get(self.xmlns('xsi', 'type'))
