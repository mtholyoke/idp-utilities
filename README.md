# IdP utility scripts

## `check-metadata.py`

This script compares `conf/metadata-providers.xml` (plus a hard-coded list of IdP metadata files) with the contents of the `metadata/` directory to make sure all required files exist, and identify any extraneous metadata files.

Future plans include validating the `id` attributes in `conf/metadata-providers.xml` (they should match the metadata filenames themselves) and comparing EntityIDs from metadata with `conf/attribute-filter.xml`.

Adding the InCommon bundle may complicate things.

## `logcheck.py`

This script has two subcommands:

**`loop`** scans one or more Tomcat (or Apache?) log files for repeated entries, consistent with the looping behavior we saw on the new production IdP from its launch in October 2020 through the fix in February 2021.

**`sp`** scans one or more `idp-process.log` files to see which service providers have received attributes from the IdP.

### Filenames

In both cases, the default file to analyze is the current (live) log file, as it would be named on the idpv4 servers: `/var/log/tomcat9/access.log` and `/opt/shibboleth-idp/logs/idp-process.log`. Use `-f` to specify a different filename.

Wildcards are allowed, and filenames that end in `.gz` can be processed without unzipping them.

**Example**

To get every SP that has used this IdP for authentication over the entire `logs/` directory:
```bash
logcheck.py sp -f /opt/shibboleth-idp/logs/
```

### Options

Currently, `loop` has no options.

For `sp`, there are two:

**`-i3`** is necessary for parsing IdP version 3 logfiles; they are in a slightly different format that cant’t easily be detected. If you forget, the only SP that shows up is “`http://shibboleth.net/ns/profiles/saml2/sso/browser`”

**`-r [entity_id]`** lets you specify a single relying party’s entity id, and _only_ processes connections to that SP. In addition to the simple count, it also outputs the list of users who have used it and the number of times for each.
