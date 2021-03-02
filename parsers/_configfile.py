#!/usr/bin/env python3

import re
import xml.etree.ElementTree as ET
from pathlib import Path


class _ConfigFile(object):
    PATH_SUB = re.compile(r'%\{(\w+(?:\.\w+)*)\}')

    XMLNS = {
        'beans': 'http://www.springframework.org/schema/beans',
        'util': 'http://www.springframework.org/schema/util',
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
            self.stanzas[id] = self.parse_stanza(child)
            print(id)
            for value in self.stanzas[id]:
                print ('  - ' + str(value))

    def make_path(self, text):
        for prop in self.PATH_SUB.finditer(text):
            stub = '%{' + prop.group(1) + '}'
            path = self.config['properties'][prop.group(1)]
            text = text.replace(stub, path)
        return Path(text)
