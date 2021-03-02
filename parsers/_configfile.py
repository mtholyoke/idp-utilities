#!/usr/bin/env python3

import re
import xml.etree.ElementTree as ET


class _ConfigFile(object):
    """
    Abstract base class for XML configuration files.

    Subclasses must implement method `parse_stanza()` to produce a
    meaningful representation of the stanzas specific to that config file.
    """

    # Pattern to use for path substitution in method `make_path()`.
    PATH_SUB = re.compile(r'%\{(\w+(?:\.\w+)*)\}')

    # Namespace URIs to use in parsing.
    XMLNS = {
        'beans': 'http://www.springframework.org/schema/beans',
        'md': 'urn:mace:shibboleth:2.0:metadata',
        'util': 'http://www.springframework.org/schema/util',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    }

    def __init__(self, config, filenames):
        self.config = config
        self.stanzas = {}
        for filename in filenames:
            self.load_stanzas(filename)

    def load_stanzas(self, filename):
        tree = ET.parse(filename)
        root = tree.getroot()
        for child in root:
            id = child.attrib.get('id')
            if id in self.stanzas:
                raise ValueError(f'Duplicate id {id} in {filename}')
            try:
                stanza = self.parse_stanza(child)
            except ValueError as ve:
                raise RuntimeError(f'Can’t load {filename}') from ve
            else:
                self.stanzas[id] = stanza

    # Interpolate path substitutions allowed by config.
    def make_path(self, text):
        for prop in self.PATH_SUB.finditer(text):
            stub = '%{' + prop.group(1) + '}'
            path = self.config['properties'][prop.group(1)]
            text = text.replace(stub, path)
        return text

    # Returns a string suitable for matching namespaced tags or attribs.
    def xmlns(self, ns, item):
        return '{' + self.XMLNS[ns] + '}' + item
