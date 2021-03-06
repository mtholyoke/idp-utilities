# IdP utility scripts

Required: Python 3.6 or greater with [PyYAML](https://pypi.org/project/PyYAML/) and [cryptography](https://pypi.org/project/cryptography/) installed.

Recommended: `xmllint`.

## `attributes.py`

This script is a simplified version of `/bin/aacli.sh` to show what attributes would be returned if the given `-n` principal (user) authenticated for the given `-r` requester (service provider).

Example:
```bash
utils/attributes.py -n jsmith -r https://sp.example.edu
```

The notable differences from the Shibboleth-supplied script are its defaults:

- Use the IdP’s hostname instead of `localhost` – can be overridden in `config.yml`
- Output in `saml2` format (including NameID, based on the SP’s metadata) — other `-f` format options are `saml1` and `json`.

If you’re verifying attributes for a `DynamicHTTPMetadataProvider` or `FileBackedHTTPMetadataProvider`, you may need a local copy of its metadata.


## `check-config.py`

Before running this script, make a copy of `config-default.yml` named `config.yml` and edit any settings that need to be changed for your installation.

This script runs three checks against the configuration files:

**First**, if you have `xmllint` installed, the script will validate all `.xml` files in `conf/` and `metadata/`. Failure in any file raises an exception and halts the script.

It then extracts three sets of files from `conf/services.xml`: metadata resolvers, attribute filters, and attribute resolvers. In all cases it excludes those with `/system/` in their path.

**Second**, it compares the contents of the metadata providers file(s) with the contents of the `metadata/` directory to make sure all required files exist, and identify any extraneous metadata files.

- Metadata files are examined to make sure they have not exceeded their `validUntil` attribute (if they have one) and that any SSL certificates in the file have not expired.

- Metadata files that exist as the result of a `FileBackedHTTPMetadataProvider` are checked if present but not required.

- Use the `metadata_require` and `metadata_ignore` keys in `config.yml` to modify the rules of which files are checked.

**Third**, it compares the attributes called for in the attribute filters with those that are resolvable using the attribute resolvers to make sure all needed attributes are accounted for, and identify any that are resolvable but used.

Future plans include validating the `id` attributes in `conf/metadata-providers.xml` (they should match the metadata filenames themselves), comparing EntityIDs from metadata with `conf/attribute-filter.xml`, and a verbose output that includes more diagnostics and warnings.


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
./logcheck.py sp -f /opt/shibboleth-idp/logs/idp-process*
```

### Options

Currently, `loop` has no options.

For `sp`, there are two:

**`-i3`** is necessary for parsing IdP version 3 logfiles; they are in a slightly different format that cant’t easily be detected. If you forget, the only SP that shows up is “`http://shibboleth.net/ns/profiles/saml2/sso/browser`”

**`-r [entity_id]`** lets you specify a single relying party’s entity id, and _only_ processes connections to that SP. In addition to the simple count, it also outputs the list of users who have used it and the number of times for each.
