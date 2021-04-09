#!/usr/bin/env python3

from ._configfile import _ConfigFile
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone
import base64
import xml.etree.ElementTree as ET


class MetadataConfig(_ConfigFile):
    """
    This is an individual metadata file.
    """
    # Inherited variables:
    #     PATH_SUB = re.compile(...)
    #     XMLNS = {...}
    # Inherited methods:
    #     __init__(self, config, filenames)
    #     make_path(self, text)
    #     translate_config(self)
    #     xmlns(self, ns, item)

    # Checks to make sure this metadata has not expired.
    # Returns array of error strings (which may be empty).
    def check_expiry(self):
        now = datetime.now(tz=timezone.utc)
        (entity_id, stanza), *_ = self.stanzas.items()
        notes = []

        vu = stanza['valid_until']
        if vu:
            if vu.endswith('Z'):
                vu = vu[:-1]
            file_expiry = datetime.fromisoformat(vu).astimezone(timezone.utc)
            if file_expiry < now:
                notes.append(f"ERROR: validUntil attribute expired {file_expiry.strftime('%Y-%m-%d %X UTC')}")
            elif file_expiry < now + timedelta(weeks=1):
                notes.append(f"WARNING: validUntil attribute will expire {file_expiry.strftime('%Y-%m-%d %X UTC')}")
        for i, cert in enumerate(stanza['certs'], start=1):
            if cert.not_valid_before.astimezone(timezone.utc) > now:
                notes.append(f'WARNING: Cert #{i} is not valid before {cert.not_valid_before} UTC')
            if cert.not_valid_after.astimezone(timezone.utc) < now:
                notes.append(f'WARNING: Cert #{i} is not valid after {cert.not_valid_after} UTC')
            elif cert.not_valid_after.astimezone(timezone.utc) < now + timedelta(weeks=4):
                notes.append(f'WARNING: Cert #{i} will not be valid after {cert.not_valid_after} UTC')
        return notes

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
        valid_until = stanza.attrib.get('validUntil')
        x509_tag = self.xmlns('ds', 'X509Certificate')
        certs = []
        for x509cert in stanza.findall(f'.//{x509_tag}'):
            text = base64.standard_b64decode(x509cert.text)
            cert = x509.load_der_x509_certificate(text, default_backend())
            certs.append(cert)
        return {
            'valid_until': valid_until,
            'certs': certs,
            'tree': stanza,
        }
