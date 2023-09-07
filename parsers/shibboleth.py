#!/usr/bin/env python3

import re
from collections import Counter
from datetime import datetime
from ._logfile import _LogEvent, _LogFile
import csv


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
        'net.shibboleth.idp.attribute.resolver.ad.impl.ContextDerivedAttributeDefinition',
        'net.shibboleth.idp.attribute.resolver.impl.AttributeResolverImpl',
        'net.shibboleth.idp.authn.AbstractUsernamePasswordCredentialValidator',
        'net.shibboleth.idp.authn.ExternalAuthenticationException',
        'net.shibboleth.idp.authn.impl.AttributeSourcedSubjectCanonicalization',
        'net.shibboleth.idp.authn.impl.FilterFlowsByForcedAuthn',
        'net.shibboleth.idp.authn.impl.FinalizeAuthentication',
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
            if self.requester is not None and audit[4] not in self.requester:
                return None
            return ShibbolethEvent(
                ip_addr=ip_addr,
                time=time,
                level=level,
                type='Attribute',
                user=audit[3],
                entity_id=audit[4],
                attributes=audit[8],
                browser=audit[20],
                audit=audit
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

    def command_scan(self):
        principal = self.principal is not None
        requester = self.requester is not None
        month = self.month is not None
        sso = self.single_sign_on is not None 
        report = {}
        sites = Counter()
        total = 0

        for event in self.events:
            # Filter the events to the ones we care about.
            if not sso:
                if event.type != "Attribute":
                    continue
            else:
                if event.type != "Attribute" and event.type != "Login":
                    continue
            if principal and event.user not in self.principal:
                continue
            if requester and event.entity_id not in self.requester:
                continue
            if month and self.month not in str(event.time):
                continue
            total += 1

            # Record what we want to keep track of.
            if principal and requester:
                # Both -n and -r: print the detail.
                print(
                    f'{event.user:8s} - {event.ip_addr:15s} - {event.time.strftime("%Y-%m-%d %H:%M:%S")} - {event.entity_id}')
            elif principal:
                # Only -n: report how many times the user visits each site.
                if event.user not in report:
                    report[event.user] = Counter()
                report[event.user][event.entity_id] += 1
            elif requester:
                # Only -r: report how many times each user visits the site.
                if event.entity_id not in report:
                    report[event.entity_id] = Counter()
                report[event.entity_id][event.user] += 1
            elif month:
                #Only -m: report how many times each user visits each site in a certain month.
                if event.entity_id not in report:
                    report[event.entity_id] = Counter()
                report[event.entity_id][event.user] += 1
            elif sso:
                """
                The intention here is to figure out how many times each user has a login 
                event, and how many times the same user has an attribute event. That way,
                the total amount of ssos for that user = attributes - logins.
                It does not currently do that, however. 
                """
                if event.type == 'Login':
                    if event.user not in report:
                        report[event.user] = Counter()
                        report[event.user][event] = 0
                elif event.type == 'Attribute':
                    if event.user not in report:
                        continue
                    report[event.user][event] += 1
                    #print("This is an sso, so count is " + str(report[event.user][event]))
            else:
                # Neither -n nor -r nor -m: count visits to each site.
                sites[event.entity_id] += 1

        
        # Output the results.
        if principal or requester or month: 
            for target in sorted(report.keys()):
                #put output in logs 
                #if month or requester:
                service = self.process_like_link(target)
                if month:
                    csvfile = open(f"./{self.output}/{service}_{self.month}.csv", 'w')
                else: 
                    csvfile = open(f"./{self.output}/{service}_all.csv", 'w')
                log = csv.writer(csvfile, delimiter = ",") 
                for item, count in sorted(report[target].items(), key=lambda x: x[1], reverse=True):
                    user = target
                    site = item
                    if requester or month:
                        user = item
                        site = target
                    log.writerow([f'{user:8s}', f'{count:6d}'])
                csvfile.close()
        else:
            """
            Put all users' count of ssos in one file.
            """
            if sso:
                csvfile = open(f"./{self.output}/user_sso_stats.csv", 'w')
                log = csv.writer(csvfile, delimiter = ",")
                for target in sorted(report.keys()):
                    for item, count in sorted(report[target].items(), key=lambda x: x[1], reverse=True):
                        user = target
                        site = item
                        log.writerow([f'{user:8s}', f'{count:6d}'])
            else:
                csvfile = open(f"./{self.output}/all_services.csv", 'w')
                log = csv.writer(csvfile, delimiter = ",")
                for item, count in sorted(sites.items(), key=lambda x: x[1], reverse=True):
                    log.writerow([f'{self.process_like_link(item)}', f'{count:6d}'])
                csvfile.close()
        print(f'{total:6d}   Total')
