# Metre Configuration

## Overview

### Files, and running config

Metre will read in a YAML config file from (normally) wherever you told it to.

After processing this, filling in defaults, and so on, it will then write this (and any ancillary files) to the "data" directory. In principle, therefore, you can look at the YAML file in this directory to understand what Metre is actually doing.

### Global, Any, and Wildcards

Metre's configuration is divided into Global values - which affect the entire running system - and per-domain values, which only affect the relevant domains.

Most domain-specific values will fall back to the `any` domain if they're not specified - there are exceptions because otherwise it can lead to a lot of typing. For example, if you block all domains by default, Metre still assumes that any other domain should be unblocked.

Wildcarded domains allow multiple domains to share a configuration, but, internally, this configuration will be templated for each domain.

## Global Settings

All global settings live within the `globals` key at the top level.

```yaml
globals:
  default-domain: example.org
```

### boot-method

Default: "none"

Boot methods are how Metre decides whether and how to fork and similar at startup.

In general, these should be set on the command line, and most people will want to run the Docker image (and, therefore, ignore this entirely).

If you are running on the command line for debug purposes, use "none".

### default-domain

Default: ""

This configures the domain to use if the remote server does not specify any domain at all.

In general, this is a bug, but still useful to support.

### rundir

Default: "/tmp" (for Docker) or "/var/run/" (for other boot methods)

Metre will typically change directory to the runtime directory after starting, and write a pid file there.

### datadir

Default: Whatever `rundir` is set to.

Metre dumps runtime configuration here (and could potentially do more later).

### log

This is a key/value containing several items:

### log.file

Default: ""

Can be set to a filename to redirect logging to a file; otherwise it'll go to console.

### log.level

Default: "info"

Can also be "warning", "error", "debug", "trace" - this is the level below which logging will be discarded. Metre's logging can get both verbose, and sensitive, at debug and trace.

### log.flush

Default: Same as `log.level`

This controls when logging is flushed. For example, setting this to "info" with level set to "trace" will buffer logging until an "info" level message is emitted.

This is a performance option.

### dnssec-keys

Default: ""

If set, a filename for loading in DNSSEC keying data. You should get this from an authenticated source, but you can also just use the Makefile's `make keys` for testing.

### fetch-crls

Default: false

If set to true, will enable CRL fetching. CRL fetching will only occur for domains that are configured to check status, which itself is off by default.

## Global Filter Settings

The top-level filters key holds one key per filter, with global filter configuration present. See filter documentation for the particular filter for what goes here.

## Domain Configuration

Domains are divided into two keys, which affect the defaults for each:

* `remote` domains are those outside the security domain
* `local` domains are those inside the security domain

### Domain Key Names

Domain key names are of three forms:

* `any` is a special key describing the defaults. This must be a `remote` domain, and will provide defaults for some configuration (noted below as "Inherits any"), and act as a catch-all for any unmatched domain. If `any` is unspecified, it will get created with the defaults for `remote` domains, except that `block` will be `true`.
* Wildcards are of the form `*.{suffix}`. More complex wildcards are unsupported. The `*` matches one or more domain labels.
* Specific domains, without wildcards, match only that domain.

### Domain Configuration

#### block

Default: `false` (but complicated)

By default, domains are not blocked, as is typical for XMPP services. Blocking a domain entirely rejects communication to or from it.

Any unspecified domain will take defaults from `any`, however, and if `any` itself is not specified in configuration, it will default to `true`.

As such, it might be better to say that only any *specifed* domain defaults to `false`.

#### transport

This block configures how to communicate with the domain.

#### transport.type

Default: `s2s`

Standard XMPP uses the XMPP S2S protocol, and this is the default.

Other protocols include `x2x`, which indicates XEP-0361, `114`, which is for Components described in XEP-0114, and `internal`, which is currently unsupported.

#### transport.multiplex

Default: true

Most XMPP servers can handle multiplexing on S2S connections, but some cannot. Metre aggressively multiplexes if possible, and turning this to false will prevent this, using a single connection for each domain pair.

Multiplexing can hide the exact domains in use over a connection (though without ECH, which Metre doesn't yet support, at least one domain will be visible).

#### transport.tls_required

Default: `true` for `remote` domains, `false` for `local` ones; however this is further altered if the `transport.type`
Inherits any: yes

Require TLS (or equivalent in principle) for confidentiality. Setting this to true does not require TLS based authentication,  just encryption.

Note this was `transport.sec` in previous versions, which is still supported.

####  transport.xmpp_ver

Default: `true`

Almost any server will handle XMPP/1.0, but some component libraries cannot, and will choke if they receive features despite supplying a version attribute in the stream open. Node.js based components are particularly affected. If you encounter this, set this to false and Metre will ignore the version attribute entirely.

#### transport.prefer

Default: `any`

By default, Metre will treat XEP-0368 or StartTLS equally, but setting this to `immediate` or `direct` will cause Metre to use offered XEP-0368 first.

Alternately, setting this to `starttls` will make Metre use such connections by default.

Metre will still honour any precedence in SRV records, and will only use these if advertised.

#### transport.connect-timeout

Default: `10`

The number of seconds to wait while trying to establish an XMPP session before giving up and trying the next advertised record.

#### stanza-timeout

Default: `20`

The number of seconds to wait while trying to send a stanza before giving up and bouncing.

#### forward

Default: `false` for `remote` domains; otherwise `true`.

Controls whether a domain should be forwarded across the security boundary at all.

This is ignored for `internal` and `114` components, on the basis that you shouldn't be hosting services on a boundary if you don't want it visible from one or other side. It'll show as a default true in the config dump though.

Otherwise the rule is simply that  Metre only forwards between domains that have different `forward` values.

#### auth block

This block controls how remote domains are authenticated (but not how Metre might authenticate itself to others).

All domain blocks must have at least one valid authentication mechanism available, otherwise it's assumed to be an error.

#### auth.pkix

Default: `true`
Inherits any: yes

Whether or not to perform PKIX authentication (i.e. certificate-based authentication).

#### auth.check-status

Default: whatever `fetch-crls` above is set to.

Ineffective if `fetch-crls` is set to false, and setting this to true but `fetch-crls` to false will cause an error.

This causes the revocation status of presented certificates to be checked. Metre uses a CRL cache, maintains CRLs for a maximum of one hour, and refetching sooner if the CRL indicates it in the nextUpdate field.

OCSP querying (and OCSP stapling) is unsupported; OCSP querying leaks a substantial amount of information, and OCSP stapling only protects the end-entity certificate.

Fetching CRLs is quite efficient, though administrators should note that Metre fetches CRLs whether or not the certificate would otherwise pass, so an attacker can (by using a CRL-DP URI in a certificate under their control) make some deductions about the traffic.

#### auth.dialback

Default: `false` for `remote` domains, otherwise `true`
Inherits any: yes

This enables authentication by XEP-0220.

Metre will always advertise, and respond to, dialback, and will also always send dialback requests to authenticated servers that are not offering SASL EXTERNAL; however, it will not authenticate remote servers by XEP-0220 unless this flag is set.

For example, a server connecting and offering a valid certificate for its domain might try dialback, and receive a positive response - but the authentication would be done by PKIX (if enabled) not dialback (if disabled).

#### auth.secret

Default: not set

If set, this is a shared secret used for authenticating XEP-0114 component connections.

In principle, this may be used in the future for TLS PSK authentication.

#### auth.host

Default: `false`

This is used for XEP-0361 X2X authentication, and is not recommended.

It will force DNSSEC to be required.

#### tls block

This block allows for control of both the PKIX identity to assume (i.e. the certificate and key pair), and also a number of TLS settings.

In some cases, Metre will learn of the identity too late to be able to place all of these in effect, and therefore Metre will use the settings for the `any` domain in those cases.

These cases are when Metre is being contacted by XEP-0368 (so does not know the calling domain), or when no SNI or stream:to/stream:from attributes have been used (so either or both identities are unknown).

#### tls.x509 block

This is used as the PKIX identity for the "local" domain on a session, i.e. the domain Metre is attempting to act as.

#### tls.x509.chain

A chain file, including the certificate.

#### tls.x509.pkey

A private key file.

#### tls.dhparam

Default: `auto`

The default, `auto`, tells OpenSSL to automatically select DH parameters, as per SSL_set_dh_auto.

Otherwise, if the value is an integer, it will be used as the maximum size of the DH parameters to be used. Metre ships with built-in DH parameters of a number of sizes: 1024, 2048, 2236, 3072, and 4096. Higher numbers than 4096 are rejected and will cause an error.

Finally, the value will be used as a filename and the DH parameters loaded in from a PEM format file.

These DH parameters are used when contacting this domain (ie, when it is the remote domain on a session).

#### tls.min_version
#### tls.max_version

Default: `TLSv1.2` minimum, no maximum.

These dictate the minimum, and maximum, versions of TLS to use when contacting this domain.

Versions are given as "TLS" (or "SSL"), followed by a 1 or 2 digit version number. "v" and "." are ignored, as is case.

So "TLSv1.2" is the same as "tls12" and will set a minimum (or maximum) TLS version.

Up to TLSv1.3 is supported, and down to SSLv2 (though this is usually disabled in the underlying OpenSSL build).

#### tls.ciphers

Default: `HIGH:!3DES:!eNULL:!aNULL:@STRENGTH`
Inherits any: yes

A cipherlist in OpenSSL format.

Again, this is used for contacting the remote domain.

#### dns block

Metre allows for DNS lookups to be overridden with static data, and also controls whether DNS records should be DNSSEC signed or not.

#### dns.dnssec_required

Default: `false` (normally; `x2x` will default this to `true`)
Inheirts any: yes

If this is set to true, any DNS lookups that fail to be DNSSEC signed will be rejected.

Records that have invalid or missing DNSSEC signatures are rejected in any case.

Override records are always treated as being DNSSEC signed.

#### dns.host

This block contains a list of host records, with keys `name` (the hostname being looked up) and `a` (the address to be returned). The address must, currently, be an IPv4 address.

#### dns.srv

This block contains a list of SRV records. Keys are:

* `host`: The hostname to be returned. Note that these are considered for PKIX as per RFC 6525.
* `tls`: True if this is a xmpps-server record, false otherwise (i.e. if this is a xmpp-server record).
* `port`: The port number, defaults to 5270 (for tls) or 5269 (otherwise).
* `weight`: SRV weight, defaults to 0.
* `priority`: SRV priority, defaults to 0.

#### dns.tlsa

This block contains TLSA records for DANE.

* `hostname`: TLSA hostname, used as key.
* `certusage`: One of CAConstraint, CertConstraint, TrustAnchorAssertion, or DomainCert.
* `matchtype`: One of Full, Sha256 or Sha512. Defaults to Full.
* `selector`: One of FullCert or SubjectPublicKeyInfo. Defaults to FullCert.
* `matchdata`: Either a filename to the data (in DER or PEM form) or base64 encoded data as a string.

#### filter-in

Filters may use, or require, a block here by name. Filters here process both TO and FROM the domain in question, but on ingress; see filter documentation for more details.
