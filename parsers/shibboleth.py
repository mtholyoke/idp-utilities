#!/usr/bin/env python3

import re
from collections import Counter
from datetime import datetime
from ._logfile import _LogEvent, _LogFile


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
    #     2: Status: 'succeeded' or 'failed'
    LOGIN_REGEX = r"^Credential Validator ldap: Login by '(.*)' (\w+)$"

    SKIP_REGEX = r"2021-06-22 01:47:10,869 - <.*> - WARN \[net.shibboleth\.idp\.authn\.impl\.LDAPCredentialValidator:182] - Credential Validator ldap: Login by <\w+> produced exception$"

    # TODO: Some of these are probably useful events
    SKIP_MODULES = [
        'net.shibboleth.idp.authn.ExternalAuthenticationException',
        'net.shibboleth.idp.attribute.resolver.impl.AttributeResolverImpl',
        'org.opensaml.security.crypto.SigningUtil',
        'org.apache.velocity.loader',
        'org.apache.velocity.directive.parse',
        'org.springframework.webflow.execution.repository.NoSuchFlowExecutionException',
        'org.springframework.webflow.execution.repository.FlowExecutionRestorationFailureException',
        'net.shibboleth.idp.saml.saml2.profile.impl.ProcessLogoutRequest',
        'org.opensaml.profile.action.impl.LogEvent',
        'Shibboleth-Audit.Logout',
        'org.opensaml.saml.common.binding.impl.SAMLMetadataLookupHandler',
        'net.shibboleth.idp.profile.impl.SelectProfileConfiguration',
        'org.opensaml.xmlsec.keyinfo.impl.BasicProviderKeyInfoCredentialResolver',
        'net.shibboleth.idp.authn.AbstractUsernamePasswordCredentialValidator',
        'org.opensaml.saml.common.binding.SAMLBindingSupport',
        'org.opensaml.saml.common.binding.security.impl.MessageReplaySecurityHandler',
        'net.shibboleth.idp.profile.impl.WebFlowMessageHandlerAdaptor',
        'org.opensaml.profile.action.impl.DecodeMessage',
        'Shibboleth-Audit.ResolverTest',
        'org.opensaml.xmlsec.algorithm.AlgorithmSupport',
        'org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler',
        'net.shibboleth.idp.ui.csrf.impl.CSRFTokenFlowExecutionListener',
        'org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler',
        'net.shibboleth.idp.session.impl.StorageBackedIdPSession',
        'net.shibboleth.idp.session.impl.DetectIdentitySwitch',
        'net.shibboleth.utilities.java.support.security.DataSealer',
        'org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder',
        'org.opensaml.storage.impl.client.ClientStorageService',
        'net.shibboleth.idp.saml.metadata.impl.ReloadingRelyingPartyMetadataProvider',
        'org.opensaml.saml.metadata.resolver.impl.AbstractMetadataResolver',
        'org.opensaml.xmlsec.impl.BasicEncryptionParametersResolver',
        'net.shibboleth.idp.saml.saml2.profile.impl.PopulateEncryptionParameters',
        'net.shibboleth.utilities.java.support.net.HttpServletSupport',
        # These were on ion but not login:
        'org.opensaml.saml.metadata.resolver.impl.AbstractReloadingMetadataResolver',
        'net.shibboleth.utilities.java.support.security.BasicKeystoreKeyStrategy',
        'net.shibboleth.idp.authn.impl.ValidateUsernamePasswordAgainstLDAP',
        'org.opensaml.messaging.decoder.servlet.BaseHttpServletRequestXMLMessageDecoder',
        'org.opensaml.saml.metadata.resolver.impl.HTTPMetadataResolver',
        'org.opensaml.saml.metadata.resolver.impl.FileBackedHTTPMetadataResolver',
        'net.shibboleth.idp.saml.nameid.impl.AttributeSourcedSAML2NameIDGenerator',
        'org.ldaptive.AbstractOperation$ReopenOperationExceptionHandler',
        'net.shibboleth.idp.saml.profile.impl.PopulateBindingAndEndpointContexts',
        'net.shibboleth.utilities.java.support.xml.BasicParserPool',
        'org.opensaml.saml.common.binding.security.impl.SAMLProtocolMessageXMLSignatureSecurityHandler',
        'net.shibboleth.idp.saml.attribute.mapping.AbstractSAMLAttributeValueMapper',
        'net.shibboleth.idp.saml.attribute.mapping.AbstractSAMLAttributeMapper',
        'org.springframework.webflow.execution.repository.BadlyFormattedFlowExecutionKeyException',
        'org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder',
        'net.shibboleth.idp.attribute.resolver.AbstractResolverPlugin',
        'org.opensaml.saml.saml2.profile.impl.AddNameIDToSubjects',
        'net.shibboleth.utilities.java.support.security.IPRangeAccessControl',
        # These were on sso but not ion or login:
        'net.shibboleth.idp.saml.attribute.mapping.AbstractSAMLAttributesMapper',
        'net.shibboleth.idp.saml.attribute.encoding.impl.SAML2StringAttributeEncoder',
        'net.shibboleth.idp.authn.AbstractUsernamePasswordValidationAction',
        'org.springframework.webflow.conversation.impl.LockTimeoutException',
        'org.opensaml.saml.saml2.binding.encoding.impl.HTTPPostEncoder',
        'org.opensaml.profile.action.impl.EncodeMessage',
        'java.lang.RuntimeException',
        'net.shibboleth.idp.profile.impl.ResolveAttributes',
        'net.shibboleth.idp.saml.nameid.impl.BaseTransientDecoder',
        'net.shibboleth.idp.saml.nameid.impl.LegacyCanonicalization',
        'net.shibboleth.idp.authn.impl.SelectSubjectCanonicalizationFlow',
        'Shibboleth-Audit.AttributeQuery',
        'org.ldaptive.pool.BlockingConnectionPool',
        'net.shibboleth.idp.saml.attribute.encoding.AbstractSAMLAttributeEncoder',
        'Shibboleth-Audit.anonymous',
        'org.opensaml.saml.common.binding.security.impl.BaseSAMLSimpleSignatureSecurityHandler',
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
                success=(login[2] == 'succeeded')
            )
        if parse['module'] == 'Shibboleth-Audit.SSO':
            audit = parse['message'].split('|')
            if self.requester is not None and entity_id not in self.requester:
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
        if re.match(self.SKIP_REGEX, parse['message']) is not None:
            return False
        return True

    def command_scan(self):
        principal = self.principal is not None
        requester = self.requester is not None
        report = {}
        sites = Counter()
        total = 0

        for event in self.events:
            # Filter the events to the ones we care about.
            if event.type != "Attribute":
                continue
            if principal and event.user not in self.principal:
                continue
            if requester and event.entity_id not in self.requester:
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
            else:
                # Neither -n nor -r: count visits to each site.
                sites[event.entity_id] += 1

        # Output the results.
        if principal or requester:
            for target in sorted(report.keys()):
                for item, count in sorted(report[target].items(), key=lambda x: x[1], reverse=True):
                    user = target
                    site = item
                    if requester:
                        user = item
                        site = target
                    print(f'{count:6d} - {user:8s} - {site}')
        else:
            for item, count in sorted(sites.items(), key=lambda x: x[1], reverse=True):
                print(f'{count:5d} - {item}')
        print(f'{total:6d}   Total')
