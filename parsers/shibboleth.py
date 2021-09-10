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

    # TODO: Some of these are probably useful events
    SKIP_MODULES = [
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
        # TODO: make this timezone-aware
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
            entity_id = audit[4] if self.idpv == 4 else audit[3]
            if self.relying_party and entity_id != self.relying_party:
                return None
            return ShibbolethEvent(
                ip_addr=ip_addr,
                time=time,
                level=level,
                type='Attribute',
                user=(audit[3] if self.idpv == 4 else audit[8]).lower(),
                entity_id=entity_id,
                # attributes=audit[8] if self.idpv == 4 else audit[10],
                # browser=audit[20] if self.idpv == 4 else 'n/a',
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

    def command_service_providers(self):
        service_providers = Counter()
        users = Counter()
        for event in self.events:
            if event.type != "Attribute":
                continue
            service_providers[event.entity_id] += 1
            if self.relying_party:
                users[event.user] += 1
        for sp, count in sorted(service_providers.items(), key=lambda x: x[1], reverse=True):
            print(f'{count:6d} - {sp}')
        if self.relying_party:
            for user in sorted(users):
                print(f'{user:8s} - {users[user]:3d}')
