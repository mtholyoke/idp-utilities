#!/usr/bin/env python3

import re
from datetime import datetime
from urllib.parse import parse_qs
from ._logfile import _LogEvent, _LogSequence, _LogFile


class TomcatEvent(_LogEvent):
    # Inherited methods:
    #     __init__(self, ip_addr, time, **kwargs)
    def __str__(self):
        return f'{self.method:4s} {self.request:27s} {self.response} {self.bytes:5d}'


class TomcatSequence(_LogSequence):
    # Inherited variable:
    #     DELTA = timedelta(minutes=5)
    # Inherited methods:
    #     __init__(self, event=None)
    #     append(self, event)
    #     first_time(self)
    #     last_time(self)
    #     limit_time(self)

    def detect_loops(self, constraints={}):
        # TODO: allow regex patterns as constraints
        previous = None
        timecode = None
        loops = {}
        for event in self.events:
            # Filter based on constraints
            eligible = True
            for constraint in constraints:
                if getattr(event, constraint, None) != constraints[constraint]:
                    eligible = False
            if not eligible:
                continue
            if str(event) == str(previous):
                if timecode not in loops:
                    loops[timecode] = [previous]
                loops[timecode].append(event)
            else:
                previous = event
                timecode = event.time.strftime("%Y-%m-%d %H:%M:%S")
        return loops


class TomcatLog(_LogFile):
    # Regex match groups:
    #     1: IP address
    #     2: Datetime as string
    #     3: HTTP method
    #     4: Request URI
    #     5: Response code as string
    #     6: '-' or number of bytes returned as string
    #     7: Referer
    #     8: User agent
    LINE_REGEX = r'^(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(\w+) (.+?) HTTP/.*?" (\d+) (.+?) "(.+?)" "(.+?)"'

    # TODO: This feels inelegant but I don’t know a Pythonic way to do it.
    SEQUENCE_CLASS = TomcatSequence

    SAML2_REGEX = r'^/idp/profile/SAML2/(Redirect|POST)/(S[LS]O)(?:\?(.*))?$'

    SKIP_PAGES = [
        '/',
        '/favicon.ico',
        '/idp/css/main.css',
        '/idp/images/mhc-logo.png',
        '/idp/profile/admin/resolvertest',
        '/idp/shibboleth',
        '/idp/status',
        '/s1log_1s01_~0_e0',
        '/robots.txt',
    ]

    # Inherited methods:
    #     __init__(self, filename='', **kwargs)
    #     find_sequences(self, index_attr='ip_addr')
    #     import_log(self, logfile)
    #     load(self, filename)

    def make_event(self, parse):
        saml2 = re.match(self.SAML2_REGEX, parse[4])
        if saml2 is None:
            print('ERROR: can’t parse', parse.string)
            return None

        request = saml2[1] + '/' + saml2[2]
        query = parse_qs(saml2[3])
        if query:
            request += '?'
            if 'SAMLRequest' in query:
                request += 'SAMLRequest'
            elif 'execution' in query:
                request += 'execution=' + query['execution'][0]
        return TomcatEvent(
            id=f'{parse[1]} {parse[8]}',
            ip_addr=parse[1],
            time=datetime.strptime(parse[2], '%d/%b/%Y:%H:%M:%S %z'),
            method=parse[3],
            request=request,
            query=query,
            response=parse[5],
            bytes=(0 if parse[6] == '-' else int(parse[6])),
            referer=parse[7],
            browser=parse[8]
        )

    def validate_line(self, parse):
        if parse[4].split('?')[0] in self.SKIP_PAGES:
            return False
        if int(parse[5]) >= 400:
            return False
        return True

    def command_loops(self):
        constraints = {
            'method': 'POST',
            'response': '200',
            # 'bytes': 3972,
        }
        self.find_sequences(index_attr='id')
        for id in self.sequences:
            for sequence in self.sequences[id]:
                ip_addr = sequence.events[0].ip_addr
                loops = sequence.detect_loops(constraints=constraints)
                for timecode in loops:
                    print(
                        f'{ip_addr:15s} {timecode} - {len(loops[timecode]):4d} - {loops[timecode][0]}')
