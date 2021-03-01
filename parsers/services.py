#!/usr/bin/env python3

import re
import xml.etree.ElementTree as ET


class ServicesConfig(object):
    XMLNS = {
        'beans': 'http://www.springframework.org/schema/beans',
        'util': 'http://www.springframework.org/schema/util',
    }

    def __init__(self, config, filename):
        self.tree = ET.parse(filename)
        self.root = self.tree.getroot()
        self.stanzas = {}
        property_regex = r'%\{(\w+(?:\.\w+)*)\}'
        for config_set in self.root.findall('util:list', self.XMLNS):
            id = config_set.attrib.get('id')
            self.stanzas[id] = []
            for value in config_set:
                if value.tag != f'{{{self.XMLNS["beans"]}}}value':
                    continue
                text = value.text
                if '/system/' in text:
                    continue
                for prop in re.finditer(property_regex, text):
                    stub = '%{' + prop.group(1) + '}'
                    path = config['properties'][prop.group(1)]
                    text = text.replace(stub, path)
                self.stanzas[id].append(text)
