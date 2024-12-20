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
        super().__init__
        self.principals = {}
        self.requesters = {}

    # TODO: add SSO back in
    def new_command_scan(self):
        # Figure out what we’re counting and how to count it.
        dash_n = self.principal is not None
        dash_r = self.requester is not None

        if not dash_n and not dash_r:
            action = 'count_both'
        elif dash_n and not dash_r:
            action = 'count_requester'
        elif dash_r and not dash_n:
            action = 'count_principal'
        else:
            action = 'output_entry'

        self.count = getattr(self, action)

        # Actually run the counts.
        for event in self.events:
            if event.type != "Attribute":
                continue
            self.count(event)

        # Output the results if we haven’t already
        if not dash_r:
            self.output_data('requesters')
        if not dash_n:
            self.output_data('principals')

    def count_both(self, e):
        self.count_principal(event)
        self.count_requester(event)

    def count_principal(self, e):
        if e['user'] not in self.principals:
            self.principals[e['user']] = Counter()
        e_date = e['time'].strftime('%Y-%m-%d')
        self.principals[e['user']][e_date] += 1

    def count_requester(self, e):
        if e['entity_id'] not in self.requesters:
            self.requesters[e['entity_id']] = Counter()
        e_date = e['time'].strftime('%Y-%m-%d')
        self.requesters[e['entity_id']][e_date] += 1

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

    def output_data(subject):
        f = sys.stdout
        if self.output:
            f = open(os.path.join(self.output, subject + '.csv'), "w")
        data = getattr(self, subject)
        if self.daily:
            # TODO: Do the thing!
        else:
            # TODO: Do the simpler thing!

    def output_entry(self, e):
        f = sys.stdout
        if self.output:
            f = open(os.path.join(self.output, 'entries.log'), "w")
        time = e.time.strftime('%Y-%m-%d %H:%M:%S')
        print(f"{time} {e.ip_addr:15s} {e.user:12s} {e.entity_id}", file=f)

    def process_like_link(self, target):
        if 'http' in target:
            if 'www.' in target:
                target = target.split('www.')[1]
            else:
                target = target.split("://")[1]
            target = target.split('/')[0]
            target_temp = target.split('.')
            target = '.'.join(target_temp[:max(len(target_temp)-1, 0)])
        return target

    def validate_line(self, parse):
        if parse['message'] == "Ignoring NameIDFormat metadata that includes the 'unspecified' format":
            return False
        return True

    """
    Takes in a string array representing an amount of requests from a user for a service and if output directory is present,
    writes them into a csv file. If output is not present, then prints.
    Parameters:
        requests(string[]): will appear as user,#requests
        service(string): name of the service user is accessing, determines which file
        the requests might go into
    Returns: None
    """
    def show_output(self, requests, service):
        if self.output:
            if self.sso:
                sso_add = "sso_"
            else:
                sso_add = ""
            if self.month:
                csvfile = open(f"./{self.output}/{service}_" + sso_add + f"{self.month}.csv", 'w')
                log = csv.writer(csvfile, delimiter = ",")
                for request in requests:
                    log.writerow(request)
                csvfile.close()
            #special case for all_services
            elif not service and self.output:
                csvfile = open(f"./{self.output}/" + sso_add + "all_services.csv", 'w')
                log = csv.writer(csvfile, delimiter = ",")
                for request in requests:
                    log.writerow(request)
                csvfile.close()
            elif self.output:
                csvfile = open(f"./{self.output}/{service}_" + sso_add + "all.csv", 'w')
                log = csv.writer(csvfile, delimiter = ",")
                for request in requests:
                    log.writerow(request)
                csvfile.close()
            else:
                for request in requests:
                    print(request)

    def command_scan(self):
        principal = self.principal is not None
        requester = self.requester is not None
        output = self.output is not None
        daily = self.daily
        sso = self.sso
        report = {}
        sites = Counter()
        total = 0
        users = []

        #ensure output folder already exists
        #if it does, create a new folder with self.output as name is self.output exists
        #if it doesn't and it's a month, quit program
        #otherwise it's fine
        #try:
           # out = open(f"./{self.output}/all_services.csv", 'r')
            #out.close()
        try:
            if not os.path.exists(os.path.join(os.getcwd(), self.output)):
                if self.output:
                    print("Output folder not present. Attempting to create...")
                    output_file = os.path.join(os.getcwd(), self.output)
                    os.mkdir(output_file)
                    print("Creation successful.")
                elif month:
                    print("Month detected with no output specified. Please provide output directory with -o.")
                    print("Quitting program...")
                    return
        except:
            pass

        for event in self.events:

            # Filter the events to the ones we care about.
            if event.type != "Attribute":
                continue
            if principal and event.user not in self.principal:
                continue
            if requester and event.entity_id not in self.requester:
                continue
            if month and self.month not in str(event.time):
                continue
            #if sso isn't True, we don't care and count as normal. If it IS true, event.sso must be true as well
            to_count = not sso or event.sso
            test = not sso
            if to_count:
                total += 1

            # Record what we want to keep track of.
            #print("to_count is " + str(to_count) + " when sso is " + str(sso) + " and event.sso is " + str(event.sso))
            if principal and requester and to_count:
                # Both -n and -r: print the detail.
                print(
                    f'{event.user:8s} - {event.ip_addr:15s} - {event.time.strftime("%Y-%m-%d %H:%M:%S")} - {event.entity_id}')
            elif principal and to_count:
                # Only -n: report how many times the user visits each site.
                if event.user not in report:
                    report[event.user] = Counter()
                report[event.user][event.entity_id] += 1
            elif requester and to_count:
                # Only -r: report how many times each user visits the site.
                if daily:
                    date = event.time.strftime('%Y-%m-%d')
                    if date not in report:
                        report[date] = Counter()
                    report[date][event.user] += 1
                    if event.user not in users:
                        users.append(event.user)
                else:
                    if event.entity_id not in report:
                        report[event.entity_id] = Counter()
                    report[event.entity_id][event.user] += 1
            elif month and to_count:
                #Only -m: report how many times each user visits each site in a certain month.
                if event.entity_id not in report:
                    report[event.entity_id] = Counter()
                report[event.entity_id][event.user] += 1
            elif to_count:
                # Neither -n nor -r nor -m: count visits to each site.
                sites[event.entity_id] += 1


        # Output the results.
        if daily:
            requests = []
            dates = sorted(report.keys())
            for user in sorted(users):
                line = [user]
                for date in dates:
                    if user in report[date]:
                        line.append(report[date][user])
                    else:
                        line.append('')
                requests.append(line)
            dates.insert(0, '')
            requests.insert(0, dates)
            self.show_output(requests, False)
        elif principal or requester or month:
            for target in sorted(report.keys()):
                #put output in logs
                service = self.process_like_link(target)
                requests = []
                for item, count in sorted(report[target].items(), key=lambda x: x[1], reverse=True):
                    user = target
                    site = item
                    if requester or month:
                        user = item
                        site = target
                    if principal and not requester:
                        requests.append(([f'{self.process_like_link(item)}', f'{count}']))
                    else:
                        requests.append(([f'{user}', f'{count}']))
                self.show_output(requests, service)
        else:
            requests = []
            for item, count in sorted(sites.items(), key=lambda x: x[1], reverse=True):
                requests.append([f'{self.process_like_link(item)}', f'{count:6d}'])
            self.show_output(requests, False)
        print(f'{total:6d}   Total')
