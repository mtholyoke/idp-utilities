#!/usr/bin/env python3

from collections import Counter
from datetime import datetime
from ._logfile import _LogEvent, _LogFile
import csv
import os
import re
import sys


class ShibbolethEvent(_LogEvent):
    # Inherited methods:
    #     __init__(self, ip_addr, time, **kwargs)
    pass


class ShibbolethLog(_LogFile):
    KEY_MAPPING = {
        'principal': 'user',
        'requester': 'entity_id',
    }

    # Regex match groups:
    #     1: Datetime with milliseconds as string
    #     2: IP address (not present in older logs)
    #     3: Log level
    #     4: Log module
    #     5: Log module line
    #     6: Message
    LINE_REGEX = r'^([0-9-]+ [0-9:,]+) - (?:(?P<ip_addr>\d+\.\d+\.\d+\.\d+) - )?(?P<level>\w+) \[(?P<module>.*?):(\d+)\] - (?P<message>.*)$'

    # Regex match groups:
    #     1: Username
    #     2: Status: one of 'succeeded', 'failed', 'produced exception'
    LOGIN_REGEX = r"^Credential Validator ldap: Login by '?(.*?)'? (.*)$"

    # Inherited variable:
    #     SEQUENCE_CLASS = _LogSequence
    # Inherited methods:
    #     __init__(self, filename='', **kwargs)
    #     find_sequences(self, index_attr='ip_addr')
    #     import_log(self, logfile)
    #     load(self, filename)

    def __init__(self, filename='', **kwargs):
        super().__init__(filename=filename, **kwargs)
        if self.daily:
            self.dates = Counter()
            self.principals = {}
            self.requesters = {}
        else:
            self.principals = Counter()
            self.requesters = Counter()

    # TODO: add SSO back in
    def command_scan(self):
        # Figure out what we’re counting and how to count it.
        if self.daily:
            action = getattr(self, 'count_daily')
        else:
            action = getattr(self, 'count_event')

        dash_n = self.principal is not None
        dash_r = self.requester is not None

        if not dash_n and not dash_r:
            count = lambda e: action('principal', e) and action('requester', e)
        elif dash_n and not dash_r:
            count = lambda e: action('requester', e)
        elif dash_r and not dash_n:
            count = lambda e: action('principal', e)
        else:
            count = lambda e: output_entry(e)

        # Actually run the counts.
        for event in self.events:
            if event.type != "Attribute":
                continue
            count(event)

        # Output the results if we haven’t already
        if not dash_r:
            self.output_data('requesters')
        if not dash_n:
            self.output_data('principals')

    def count_daily(self, subject, e):
        store = getattr(self, f"{subject}s")
        datum = getattr(e, self.KEY_MAPPING[subject])
        if datum not in store:
            store[datum] = Counter()
        e_date = e['time'].strftime('%Y-%m-%d')
        store[datum][e_date] += 1
        self.dates[e_date] += 1

    def count_event(self, subject, e):
        store = getattr(self, f"{subject}s")
        datum = getattr(e, self.KEY_MAPPING[subject])
        store[datum] += 1

    def make_event(self, parse):
        ip_addr = parse['ip_addr']
        # TODO: make this timezone-aware.
        timestamp = parse[1] + '000'
        time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S,%f')
        level = parse['level']

        if parse['module'].endswith('LDAPCredentialValidator'):
            login = re.match(self.LOGIN_REGEX, parse['message'])
            if login is None:
                print('ERROR: can’t parse message', parse.string)
                return None
            if self.principal and login[1].lower() not in self.principal:
                return None
            return ShibbolethEvent(
                ip_addr=ip_addr,
                time=time,
                level=level,
                type='Login',
                user=login[1].lower(),
                success=(login[2] == 'succeeded'),
            )
        if parse['module'] == 'Shibboleth-Audit.SSO':
            audit = parse['message'].split('|')
            if self.principal and audit[3].lower() not in self.principal:
                return None
            if self.requester and audit[4] not in self.requester:
                return None
            return ShibbolethEvent(
                ip_addr=ip_addr,
                time=time,
                level=level,
                type='Attribute',
                user=audit[3].lower(),
                entity_id=audit[4],
                attributes=audit[8],
                browser=audit[20],
                audit=audit,
                sso=(self.events[-1].type != 'Login'),
            )
        # print('Unknown log module:', parse['module'])
        return None

    def output_daily(self, data, f):
        writer = csv.writer(f, delimiter = ",")
        dates = sorted(self.dates.keys())
        writer.writerow(['user'].extend(dates))
        for user in sorted(data.keys()):
            row = [user]
            for date in dates:
                if data[user][date] > 0:
                    row.append(data[user][date])
                else:
                    row.append(None)
            writer.writerow(row)

    def output_data(self, subject):
        f = sys.stdout
        if self.output:
            f = open(os.path.join(self.output, subject + '.csv'), 'w')
        data = getattr(self, subject)
        if self.daily:
            self.output_daily(data, f)
        else:
            self.output_simple(data, f)

    def output_entry(self, e):
        f = sys.stdout
        if self.output:
            f = open(os.path.join(self.output, 'entries.log'), 'w')
        time = e.time.strftime('%Y-%m-%d %H:%M:%S')
        print(f"{time} {e.ip_addr:15s} {e.user:12s} {e.entity_id}", file=f)

    def output_simple(self, data, f):
        writer = csv.writer(f, delimiter = ",")
        for row in sorted(data.items(), key=lambda x: x[1], reverse=True):
            writer.writerow(row)

    def validate_line(self, parse):
        if parse['message'] == "Ignoring NameIDFormat metadata that includes the 'unspecified' format":
            return False
        return True
