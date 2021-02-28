#!/usr/bin/env python3

import gzip
import re
from datetime import timedelta


class _LogEvent(object):
    def __init__(self, ip_addr, time, **kwargs):
        self.ip_addr = ip_addr
        self.time = time
        for key, value in kwargs.items():
            setattr(self, key, value)


class _LogSequence(object):
    DELTA = timedelta(minutes=5)

    def __init__(self, event=None):
        self.events = []
        if event:
            self.append(event)

    def append(self, event):
        self.events.append(event)

    def first_time(self):
        return None if not self.events else self.events[0].time

    def last_time(self):
        return None if not self.events else self.events[-1].time

    def limit_time(self):
        if not self.events or not self.last_time():
            return None
        return self.last_time() + self.DELTA


class _LogFile(object):
    LINE_REGEX = r'^(.*)$'
    SEQUENCE_CLASS = _LogSequence

    def __init__(self, filename='', **kwargs):
        self.events = []
        self.sequences = {}
        for key, value in kwargs.items():
            if key in ['events', 'sequences']:
                raise ValueError
            setattr(self, key, value)
        if filename:
            self.load(filename)

    def find_sequences(self, index_attr='ip_addr'):
        for event in self.events:
            index = getattr(event, index_attr)
            if index not in self.sequences:
                self.sequences[index] = [self.SEQUENCE_CLASS(event)]
                continue
            if event.time > self.sequences[index][-1].limit_time():
                self.sequences[index].append(self.SEQUENCE_CLASS())
            self.sequences[index][-1].append(event)

    def import_log(self, logfile):
        for logline in logfile:
            if isinstance(logline, bytes):
                logline = logline.decode()
            parse = re.match(self.LINE_REGEX, logline)
            if parse is None:
                continue
            if not self.validate_line(parse):
                continue
            event = self.make_event(parse)
            if event:
                self.events.append(event)

    def load(self, filename):
        if filename.endswith('.gz'):
            logfile = gzip.open(filename)
        else:
            logfile = open(filename)
        self.import_log(logfile)

    # Override this in a subclass
    # Original line available as parse.string
    def make_event(self, parse):
        return None

    # Override this in a subclass
    # Original line available as parse.string
    def validate_line(self, parse):
        return True
