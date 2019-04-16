# Configuration

Metre's configuration file is an XML file. Currently, there is no schema, but this document should guide you through it.

There are also a set of example configurations for various scenarios, with the details explained.

## Overview

The configuration file always holds the root element `config`, and is qualified by the XML namespace URI `http://surevine.com/xmlns/metre/config`:

```xml
<config xmlns="http://sureivne.com/xmlns/metre/config">
  <!-- Config goes here -->
</config>
```

When run, Metre's first action is to parse this configuration file, and then write it out to the data directory, with all defaults expanded, and the file annotated. The filename will be `metre.running.xml`. This means that in the event things are not working the way you expect, it's a good idea to check the existence and contents of this file.

The defaults can be complex - Metre will change defaults depending on how other options are set. Typically, setting a global option will cause per-domain defaults to change, and setting an option on the special `<any/>` domain entry will cause other domain's defaults to change. Metre's design is around *smart defaults*, meaning that in general, the defaults are the ones we expect people to want.

An example is that if you set the `<any/>` domain entry require TLS, we expect you mean that for all domains unless stated otherwise. But if you set it to `block` all communication, we expect you'd still prefer to allow communication for other domains by default. Similarly, if you don't even have an `<any/>` domain entry, we think you want to block unspecified domains by default - but if you include one the default is not to block. 

## Sections

There are four sections to the configuration file. We'll explain them each in turn. Each section is a single XML element, which contains elements specific to that section.

### Globals

The Globals section contains operational defaults for the deployment.

```xml
<globals>
  <!-- Global settings -->
</globals>
```

#### Domain

The `domain` element has a single attribute, `name`, which provides the default domain for the deployment. In some cases, remote peers will not provide a requested domain in stream headers, and in these cases, Metre cannot know which domain to use to look up various other defaults - including TLS certificates.

While a properly-behaving XMPP server will always provide a name (if not in the initial stream header, perhaps via TLS SNI), this is a useful fallback.

```xml
<domain name="shakespeare.example"/>
```

#### Runtime Directory

The `rundir` element contains a path to a runtime directory. This will typically be used as the working directory for Metre, and may have PID files written to it. A sensible choice - and the default - is `/var/run/`.

```xml
<rundir>/tmp</rundir>
```

#### Log file

Metre will emit fairly intensive logging to a file based on the filename given in the `logfile` element. We use `spdlog`, so a filename given as `/var/log/metre/metre.log` will probably generate logging into `/var/log/metre/metre_2019-04-14.log` or similar.

The default here will be `/var/log/metre/metre.log`, unless Metre is started using the `systemd` boot method, in which case it will log to `stdout` in the typical systemd method.

```xml
<logfile>/tmp/testing.log</logfile>
```

#### Boot Method

The `boot_method` gives the mechanism by which Metre is started. There are a number of these, depending on platform. You can override this by using the `-d` command line argument. All boot methods will cause various changes to defaults, and in some cases will override config options.

On all platforms, `none` will cause Metre to run in the foreground - this is useful for debugging and where process management will occur at a higher level.

On Linux, there's `systemd`, which will start Metre in a way compatible with the SystemD init system. This will make logging emit through stdout.

Also on Linux, `sysv` will cause Metre to fork and detach from the controlling terminal in traditional "Daemon" style, suitable for launching from SysV and similar init systems.

The final Linux method is `docker`, which is similar to `none`, but will make various configuration changes suitable for the official docker image.

On Windows, there is `service`, which will cause Metre to assume it is being run as a Windows Service.

```xml
<boot_method>sysv</boot_method>
```

The default is `none` on Linux, and `service` on Windows.

#### Data Directory

The `datadir` element provides a directory which Metre can write various runtime files. Most notably, Metre dumps the running configuration here after launch.

```xml
<datadir>/var/tmp/</datadir>
```

This defaults to the same as the Runtime Directory.

#### DNSSEC Key file

The `dnssec` element contains a full path to the DNSSEC Key File used to initialize DNS SEC support. This is in zone format, and will need to be obtained securely. The format will be the same as the output of `dig . DNSKEY` - but you'll need to ensure the contents are properly verified.

```xml
<dnssec>/etc/metre/keys
``` 

The default is to disable DNSSEC.

#### Fetch CRLs

By default, Metre will fetch CRLs given by the CRL Distribution Point attribute in certificates. These will then be used to validate certificate status.

Setting this to `false` disables all CRL fetching (and, by inference, all certificate status checks).

#### Filter Global Configuration

Filters are compiled-in traffic processors. These have independent configuration specified within a global `filter` element.

### Domains

Peer domains are configured within two different sections - `local` and `remote`. These sections are identical except for the defaults. In general terms, you'll always be using the `remote` section and leaving out the `local` section entirely, since Metre's support for local services isn't intended for more than testing.

A domain defined in local defaults to a transport type of `internal`, and will respond to XEP-0199 "Ping" requests.

The remainder of this section assumes that the section is `remote`.

#### Domain Search

If Metre receives a request to or from a domain that does not have a configuration block, it will search for a parent matching block. This is done by searching for *wildcard* matches for the parent domains in turn, and eventually looking at the `<any/>` block for defaults. Therefore a domain such as `dave.cridland.net` will have the following searches:

1. `dave.cridland.net`
1. `*.cridland.net`
1. `*.net`
1. `<any/>`

The `<any/>` block is simply a domain block like any other except that its defaults are derived from global settings - every other domain block's defaults are derived from the `<any/>` block.

A normal domain block uses the `domain` element with a `name` attribute specifying the domain name or wildcard.

Otherwise, both `domain` and `any` share the same attributes and child elements.

#### Blocking Communication

A `block` attribute specifies whether Metre should allow any communcation to or from the domain. The default is to allow communication to any domain for which there is a block in the configuration file (including `<any/>`), and deny communication to any other domain.

#### Forwarding Communication

Domains that have the `forward` attribute set will have communications forwarded for them - meaning that Metre will act at as the domain for other parties, or act as the other party for them. In practical terms, this means in order to have communication flow between two domains:

* At least one must have `forward` set.
* Neither may have `block` set.

Forward defaults to `false` for most domains, however a domain with a transport type of `114` will default to forwarding.

#### Timeouts

There are two timeouts, both controlled by child elements of a domain:

* `connect-timeout` is the timeout for attempts to connect to a remote host for this domain. This timeout includes DNS lookups as well as TCP connections and initial XMLStream setup.
* `stanza-timeout` is the total timeout for a stanza request. This may include multiple connection attempts.

#### Transports

Peer domains need to be talked to somehow, and a transport defines how.

A transport is held in an element `transport`, which has two attributes:

* The `type` - known as the transport type, defines the method to establishing a link and sending stanzas. There are four types currently supported:
 1. `s2s` is the standard RFC 6121 Server to Server connection.
 1. `114` is the Component method defined in XEP-0114.
 1. `x2x` is the lightweight S2S known as X2X, and defined in XEP-0361.
 1. `internal` is for domains actually hosted by Metre.
* The `sec` attribute controls the required security (always TLS). This generally defaults to `true`, except for Components, where it defaults to `false`.

Transports contain `auth` elements which control what types of authentication are deemed sufficient. The `type` attribute gives the type of authentication:

* `pkix` authenticates remote domains by checking the X.509 certificate offered during TLS. A child element `check-status` controls whether to check status via CRLs - if CRL fetching is disabled then setting this will cause an error
* `dialback` authenticates remote domains by using XEP-0220. Note that Metre uses the enhancements defined in XEP-0344, and will therefore send and respond to dialback requests even if dialback itself cannot be used to authenticate.
* `secret` is used for Component domains, which requeire a secret (given as the element's value). Future versions of Metre may support a Preshared Key within TLS, or SASL, for S2S.
* `host` is used by X2X. Using host-based authentication is not generally recommended and will require DNSSEC by default.

```xml
<transport type="s2s" sec="true">
  <auth type="pkix"><check-status/></auth>
  <auth type="dialback"/>
  <auth type="secret">MyPassword!</auth><!-- Doesn't yet work with S2S -->
  <auth type="host"/><!-- Doesn't yet work with S2S -->
</transport>
```

#### TLS Configuration

There are a series of configurables regarding TLS. The primary one is `x509`, which configures the certificate and private key used when acting as the domain. This has two attributes, a `chain` and `pkey`, both of which take either PEM format files for the chain and private key respectively.

*If users wish support for DER, PKCS#11, or CHM, please ask!*

```xml
<x509 chain="chain.pem" pkey="key.pem"/>
``` 

Cipher suites can be configured by a `ciphers` element, which has a value of an OpenSSL-style cipher specification string. The default is currently `HIGH:!3DES:!eNULL:!aNULL:@STRENGTH` which is carefully constructed to score well on third-party testing.

```xml
<ciphers>DEFAULT</ciphers>
``` 

Finally, the DH parameter size can be chosen by `size` attribute of the `dhparam` element. Valid values are `1024`, `2048`, or `4096` - which is the default. DH parameters are currently compiled in, and security-sensitive deployments are advised to regenerate and rebuild.

```xml
<dhparam size="2048"/>
```

Configuration is always picked from the local domain.

The actual configuration for TLS can be complicated by whether a domain is known at the point where the TLS context is created, and also whether the session is inbound or outbound. Where the domain is known - a classical S2S session where the peer has specified a requested ("to") domain in the stream header - all the configuration will be gathered from the expected domain.

For other cases - including XEP-0368 - the context will be selected based on the default domain. If the peer uses the SNI extension, the certificate will be selected based on that.

On outbound connections, the local domain is always known.

#### DNS Configuration

Metre, like any XMPP server, obtains connection information via DNS. Further, it can obtain information about the expected X.509 certificate and/or chain via DNS as well. DNSSEC is supported if configured with a key file, and this can be mandated. Finally, each record type can be overridden where DNS is undesirable or not available.

All DNS configuration is gathered under a single `dns` element, which has an attribute `dnssec`. If that's set, then all DNS lookups must be secured with DNSSEC - however, any override records are also considered to be secured this way. DNSSEC defaults to false.

Within the `dns` element are any overrides required:

* `srv` elements hold SRV lookups. The domain is not specified. In order to switch from a `_xmpp-server._tcp.` prefix to a XEP-0368-style `_xmpps-server._tcp.` prefix, the `tls` attribute can be set. The results will the the `host` and `port` attributes, and the `priority` and `weight` can be configured as well if desired. Everything other than `host` will default sensibly. 
* `host` elements hold A and AAAA lookups. The `a` attribute holds either an IPv4 address in "Dotted Quad" notation or an IPv6 address in normal notation.
* `tlsa` elements hold TLSA lookups. These hold information about expected TLS certificates from the peer.

TLSA records follow RFC 6698, which should be consulted for detailed behaviour, but an overview is that there is a certificate usage, match type, and selector, and the data to match.

We hold the certificate usage field in the attribute `certusage`. The values, taken from the RFC, are:

* `CAConstraint`  -  The certificate must be chained back to this known trust anchor (so the CA referred to here must be a system trusted CA, and the certificate must be valid according to standard PKIX).
* `CertConstraint`  - The certificate must match the one referred to here, but must also be valid according to PKIX. 
* `TrustAnchorAssertion`  - Here, the certificate chains back to this trust anchor, which may be otherwise unknown to Metre. 
* `DomainCert`  - This merely matches the certificate, and otherwise ignores PKIX.

The certificate itself is specified using two different attributes:

* `matchtype` can be `Sha256`, `Sha512`, or `Full`.
* `selector` indicates whether the data should be the `FullCert` or just the `SubjectPublicKeyInfo`.

Finally, the value of the element is one of:

* A hex-notation hash value, for the hash `matchtype`s.
* A base64-encoded DER value of the data for any `matchtype` of `Full`. 
* For `Full` matches of `FullCert`, this can additionally be a filename.

#### Domain Filters

Finally, filters can also have configuration blocks within a `filters-in` element.
