#!/usr/bin/env python3

import re
import xml.etree.ElementTree as ET
from pathlib import Path


class _ConfigFile(object):
    PATH_SUB = re.compile(r'%\{(\w+(?:\.\w+)*)\}')

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
                raise RuntimeError(f'Can’t load {filename}) from ve')
            else:
                self.stanzas[id] = stanza

    def make_path(self, text):
        for prop in self.PATH_SUB.finditer(text):
            stub = '%{' + prop.group(1) + '}'
            path = self.config['properties'][prop.group(1)]
            text = text.replace(stub, path)
        return Path(text)

    def xmlns(self, ns, item):
        return '{' + self.XMLNS[ns] + '}' + item
