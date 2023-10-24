#!/usr/bin/env python3

import re
from collections import Counter
from datetime import datetime
from ._logfile import _LogEvent, _LogFile
import csv
import os


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
    LOGIN_REGEX = r"^Credential Validator ldap: Login by '?(.*)'? (\w+)$"

    # TODO: Some of these are probably useful events
    SKIP_MODULES = [
        'DEPRECATED',
        'java.lang.IllegalStateException',
        'net.shibboleth.idp.authn.impl.FinalizeAuthentication',
        'net.shibboleth.idp.attribute.resolver.ad.impl.ContextDerivedAttributeDefinition',
        'net.shibboleth.idp.attribute.resolver.impl.AttributeResolverImpl',
        'net.shibboleth.idp.authn.AbstractUsernamePasswordCredentialValidator',
        'net.shibboleth.idp.authn.ExternalAuthenticationException',
        'net.shibboleth.idp.authn.impl.AttributeSourcedSubjectCanonicalization',
        'net.shibboleth.idp.authn.impl.FilterFlowsByForcedAuthn',
        'net.shibboleth.idp.authn.impl.SelectAuthenticationFlow',
        'net.shibboleth.idp.profile.impl.SelectProfileConfiguration',
        'net.shibboleth.idp.profile.impl.WebFlowMessageHandlerAdaptor',
        'net.shibboleth.idp.saml.attribute.transcoding.impl.SAML2StringAttributeTranscoder',
        'net.shibboleth.idp.saml.metadata.impl.ReloadingRelyingPartyMetadataProvider',
        'net.shibboleth.idp.saml.saml2.profile.impl.PopulateEncryptionParameters',
        'net.shibboleth.idp.saml.saml2.profile.impl.ProcessLogoutRequest',
        'net.shibboleth.idp.saml.saml2.profile.impl.ValidateSAMLAuthentication',
        'net.shibboleth.idp.session.impl.DetectIdentitySwitch',
        'net.shibboleth.idp.session.impl.ProcessLogout',
        'net.shibboleth.idp.session.impl.StorageBackedIdPSession',
        'net.shibboleth.idp.ui.csrf.impl.CSRFTokenFlowExecutionListener',
        'net.shibboleth.utilities.java.support.net.HttpServletSupport',
        'net.shibboleth.utilities.java.support.security.DataSealer',
        'net.shibboleth.utilities.java.support.security.impl.IPRangeAccessControl',
        'org.apache.velocity.directive.parse',
        'org.apache.velocity.loader',
        'org.opensaml.profile.action.impl.DecodeMessage',
        'org.opensaml.profile.action.impl.LogEvent',
        'org.opensaml.saml.common.binding.impl.SAMLMetadataLookupHandler',
        'org.opensaml.saml.common.binding.SAMLBindingSupport',
        'org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler',
        'org.opensaml.saml.common.binding.security.impl.MessageReplaySecurityHandler',
        'org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler',
        'org.opensaml.saml.metadata.resolver.impl.AbstractMetadataResolver',
        'org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder',
        'org.opensaml.security.crypto.SigningUtil',
        'org.opensaml.storage.impl.client.ClientStorageService',
        'org.opensaml.xmlsec.algorithm.AlgorithmSupport',
        'org.opensaml.xmlsec.impl.BasicEncryptionParametersResolver',
        'org.opensaml.xmlsec.keyinfo.impl.BasicProviderKeyInfoCredentialResolver',
        'org.springframework.webflow.execution.FlowExecutionException',
        'org.springframework.webflow.execution.repository.FlowExecutionRestorationFailureException',
        'org.springframework.webflow.execution.repository.NoSuchFlowExecutionException',
        'Shibboleth-Audit.Login',
        'Shibboleth-Audit.Logout',
        'Shibboleth-Audit.ResolverTest',
        # These were on ion but not login:
        'net.shibboleth.idp.attribute.resolver.AbstractResolverPlugin',
        'net.shibboleth.idp.authn.impl.ValidateUsernamePasswordAgainstLDAP',
        'net.shibboleth.idp.saml.attribute.mapping.AbstractSAMLAttributeMapper',
        'net.shibboleth.idp.saml.attribute.mapping.AbstractSAMLAttributeValueMapper',
        'net.shibboleth.idp.saml.nameid.impl.AttributeSourcedSAML2NameIDGenerator',
        'net.shibboleth.idp.saml.profile.impl.PopulateBindingAndEndpointContexts',
        'net.shibboleth.utilities.java.support.security.BasicKeystoreKeyStrategy',
        'net.shibboleth.utilities.java.support.security.IPRangeAccessControl',
        'net.shibboleth.utilities.java.support.xml.BasicParserPool',
        'org.ldaptive.AbstractOperation$ReopenOperationExceptionHandler',
        'org.opensaml.messaging.decoder.servlet.BaseHttpServletRequestXMLMessageDecoder',
        'org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler',
        'org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver',
        'org.opensaml.saml.metadata.resolver.impl.FileBackedHTTPMetadataResolver',
        'org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver',
        'org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder',
        'org.opensaml.saml.saml2.profile.impl.AddNameIDToSubjects',
        'org.springframework.webflow.execution.repository.BadlyFormattedFlowExecutionKeyException',
        # These were on sso but not ion or login:
        'java.lang.RuntimeException',
        'net.shibboleth.idp.authn.AbstractUsernamePasswordValidationAction',
        'net.shibboleth.idp.authn.impl.SelectSubjectCanonicalizationFlow',
        'net.shibboleth.idp.profile.impl.ResolveAttributes',
        'net.shibboleth.idp.saml.attribute.encoding.AbstractSAMLAttributeEncoder',
        'net.shibboleth.idp.saml.attribute.encoding.impl.SAML2StringAttributeEncoder',
        'net.shibboleth.idp.saml.attribute.mapping.AbstractSAMLAttributesMapper',
        'net.shibboleth.idp.saml.nameid.impl.BaseTransientDecoder',
        'net.shibboleth.idp.saml.nameid.impl.LegacyCanonicalization',
        'org.ldaptive.pool.BlockingConnectionPool',
        'org.opensaml.profile.action.impl.EncodeMessage',
        'org.opensaml.saml.common.binding.security.impl.BaseSAMLSimpleSignatureSecurityHandler',
        'org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder',
        'org.springframework.webflow.conversation.impl.LockTimeoutException',
        'Shibboleth-Audit.anonymous',
        'Shibboleth-Audit.AttributeQuery',
        # These were only on idp5:
        'net.shibboleth.ext.spring.error.ExtendedMappingExceptionResolver',
        'net.shibboleth.idp.authn.PooledTemplateSearchDnResolver',
    ]
    # Inherited variable:
    #     SEQUENCE_CLASS = _LogSequence
    # Inherited methods:
    #     __init__(self, filename='', **kwargs)
    #     find_sequences(self, index_attr='ip_addr')
    #     import_log(self, logfile)
    #     load(self, filename)

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
            if self.events[-1].type == 'Login':
                return ShibbolethEvent(
                    ip_addr=ip_addr,
                    time=time,
                    level=level,
                    type='Attribute',
                    user=audit[3],
                    entity_id=audit[4],
                    attributes=audit[8],
                    browser=audit[20],
                    audit=audit,
                    sso=False
            )
            else:
                return ShibbolethEvent(
                    ip_addr=ip_addr,
                    time=time,
                    level=level,
                    type='Attribute',
                    user=audit[3],
                    entity_id=audit[4],
                    attributes=audit[8],
                    browser=audit[20],
                    audit=audit,
                    sso=True
                )
        print('Unknown log module:', parse['module'])
        return None

    def validate_line(self, parse):
        if parse['module'] in self.SKIP_MODULES:
            return False
        if parse['message'] == "Ignoring NameIDFormat metadata that includes the 'unspecified' format":
            return False
        return True
    
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
        month = self.month is not None
        output = self.output is not None
        sso = self.sso
        report = {}
        sites = Counter()
        total = 0

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
        if principal or requester or month:
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