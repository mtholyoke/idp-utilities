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
            # entity_id = audit[4] if self.idpv == 4 else audit[3]
            entity_id = audit[4] #cuts out i3
            if self.relying_party and entity_id != self.relying_party:
                return None
            return ShibbolethEvent(
                ip_addr=ip_addr,
                time=time,
                level=level,
                type='Attribute',
                # user=(audit[3] if self.idpv == 4 else audit[8]).lower(),
                user = audit[3], # cuts out i3
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


    # entity_id = user
    # relying_party = link
    # returns a list of each relying_party accessed by particular user (and how many times)
    # e.g.
    # https://myhealth.mtholyoke.edu/shibboleth 1
    # https://c66-shib.symplicity.com/sso/ 5
    # ...
    def command_relying_parties(self): # function is passed list containing idpv and relying_party
        tot_count = 0 # keeps total count of links(relying_party) accessed by the user
        relying_parties = Counter() # keep track of the number of accesses for each relying_party
        for event in self.events:
            if event.type != "Attribute":
                continue
            if event.user == self.name: #if the link we're looking at has been accessed by the given user
                relying_parties[event.entity_id] += 1 #increment the number of times the link has been accessed
                tot_count += 1
        print(f'{tot_count} - {self.name}')
        if self.name:
            for party in sorted(relying_parties):
                print(f'{party:8s} - {relying_parties[party]:3d}')



    # returns a list of each user that accessed a given link(relying_party) and the number of times they did so
    # e.g.
    # swett22n -   1
    # tarab22d -   1
    # tavar22a -   1
    # ...
    def command_service_providers(self): # function is passed list containing idpv and relying_party
        service_providers = Counter() #keeps total count of accesses for each relying_party
        users = Counter() # keep track of the number of access times for each user
        for event in self.events:
            if event.type != "Attribute":
                continue
            service_providers[event.entity_id] += 1
            if self.relying_party:
                users[event.user] += 1 #increment the number of times the user has visited the link
            # if self.name:
            #     if self.name[0] == event.user:
                    # user_count+=1
        # if self.name:
        #     if self.name[0] == event.user:
        #         print("HI")
        #         print(f'{user_count} - {self.relying_party}')
        #     return 0
                # if self.name:
                #     print("HI")
        for sp, count in sorted(service_providers.items(), key=lambda x: x[1], reverse=True): #prints the count of each user access
            if not self.name: # we don't need to print the total count if -n has been specified
                print(f'{count:6d} - {sp}') #prints out total count of user accesses and the relying_party

        # figure out whether -n and -r have both been specified. If so, print intersection
        # if self.relying_party and self.name:
        #     print("Both")
        #     print(f'{service_providers.items()} - {self.name}')
        #     return 0
        if self.relying_party:
            for user in sorted(users):
                if not self.name or self.name[0] == user: # if -n has been specified, we only need to print the count of 1 user
                    print(f'{user:8s} - {users[user]:3d}') # for each user in the list, print out the username
