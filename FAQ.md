Metre FAQ
==========

Why not call it Meter?
-----

Metre is the right spelling. It's also the form typically used (even in US English) for poetry,
and XMPP often uses poetry terms (like stanza).

Who is "I"?
----

I am Dave Cridland. You can find me in various places. If you're using Metre, or interested in doing so,
please drop me a line, or an IM, or whatever.

Can I get support from you?
----

[Surevine Ltd](https://www.surevine.com/) used to (and maybe still does) do support contracts. 

Is this an XMPP server?
----

Well... Sort of. You can't connect clients to it, only servers and components (which are
sort of servers anyway). It can offer services - but it actually only provides XEP-0199
ping responses which are useful for diagnostics and testing. I might add version, eventually.

What it's for is for hosting components outside of a full server, and for letting two
servers which cannot, or must not, talk to each other directly connect through it "back to back".

So if you have a number of internal services which cannot be exposed, or cannot perform
the required security, you can have those setup as "forwarded" domains, and Metre will respond
to other, non-forwarded domains pretending to be them. As an example, if you want to expose
your service `example.com` to the world, but you don't want to risk having it directly accessible,
then you'd put Metre in your DMZ, have `example.com` connect to it, instead of the internet,
and then the world will connect to Metre.

Metre does need your TLS certificate and private key, however. It is acting as a "Man in
the middle", joining two security domains - the world (the outer domain) sees Metre as
being your XMPP Server, whereas your XMPP Server sees Metre as being, in effect, the world.

Example:

```yaml
remote:
  example.com:
    transport:
      type: s2s
      sec: false
    auth:
      dialback: true
  any:
    transport:
      type: s2s
      sec: true
    tls:
      x509:
        chain: chain-file.pem
        pkey: keyfile.pem
```

How production-ready is this?
----

It has been used in production for years. However, I would recommend you grab hold of me.

Does it score OK on the IM Observatory?
----

It can get an A without much effort; the defaults are designed around this. 

The defaults look complex!
----

Yes, they are - Metre tries to be smart about what defaults to use for a domain given
previous configuration. For example, if it's set to fetch certificate status information (a global), it'll also
check a per-domain option for it. The per-domain option will default to what makes sense - if
it's set to fetch certificate status globally, the per-domain option defaults to true.

Domains should inherit defaults from the `any` domain, too.

If you're confused, check the config dump that'll be created in the data directory - it'll
contain all the configuration, including defaults, and should be an accurate snapshot of the
running config (very useful for debugging and support!).

SIGHUP doesn't do a reload!
----

What Metre needs to do on a reload is flush all security information, disconnect all S2S
sessions and components that may have changed security parameters, and ensure that
all trust anchors on-disk are up to date.

Essentially, it may have to discard all runtime state. And figuring out exactly what runtime
state is safe to maintain, and therefore which sessions are safe to persist across this reload,
is fraught with danger of getting things wrong. So I've elected not to try - if you change the
configuration file, just restart - it really is much safer that way.

You will not disrupt connected clients - those connect to your real XMPP Server, not this one.

I'm connecting a Java server and...
----

Java, until recently, couldn't handle reasonable DH parameters used for Perfect
Forward Secrecy, and would choke.

Even now, you'll need to lower DH parameter sizes for that server - you can do this
with either `dhparam: "1024"` or `dhparam: "2048"` (for Java7 and Java8)
within the domain stanza for the Java server. Metre picks the DH parameter size
based on the minimum of the requested, and the minimum configured size.

Example:

```yaml
  "tigase.example.com"
    tls:
      dhparam:
        size: '1024'
```

My internal server only supports 3DES...
----

Just as with DH parameters, you can change the cipher suites as well for certain servers.

Just change the `ciphers` directive to allow the ciphers you need. It's a traditional OpenSSL cipher list.

The default is (currently) `HIGH:!3DES:!aNULL:!eNULL:@STRENGTH`

Example:

```yaml
  "ms-dos.example.com":
    tls:
        ciphers: DEFAULT
```

I'm trying to connect to a domain hosted on Google, and ...
----

Google's broken GTalk service is largely unmaintained, and never supported any kind
of TLS. Metre requires TLS by default, but you can change that within the transport definition
by adding a `sec: false` attribute to the transport. You'll almost certainly want to enable
dialback for these.

Example:

```yaml
  "google.example.com":
     transport:
       type: s2s
       sec: false
     auth:
       dialback: true
```

When does a config item get used?
----

In general, any session is identifiable by two domains - whatever Metre is
acting as, and the remote domain. Most configuration is about the remote domain,
and in some cases (particularly TLS controls when handling inbound XEP-0368),
we won't know this early enough and will have to use `any` settings.

`dhparam`, `ciphers`, and `transport` are all based on the remote server. So in the examples above,
google.example.com will be expected to be over S2S, with optional TLS, ms-dos.example.com will
have basic ciphers, and so on.

In particular, the authentication methods (pkix, dialback, and secret) are how Metre will
authenticate the remote domain, and not how it will authenticate itself *to* the remote domain.

Similarly, the `dns` stanza controls lookups associated with the remote domain (so you can
override host lookups for just one domain, even if the host is also used by another).

However the `x509` identity is how Metre will behave for the domain when it's acting as it locally, and not what it'll
be expecting when connecting remotely.

How are XEP-0114 components hosted?
----

XEP-0114 components are, to Metre, just another kind of remote server, albeit one it
cannot initiate a connection to. The difference is that you'll need to define the `transport` type as "114",
and set a secret for the authentication with a `auth: secret`, containing the authentication secret, like so:

```yaml
"component.example.com":
  transport:
    type: "114"
  auth:
    secret: "S3Kr3T!"
```

Most component libraries will not negotiate TLS, so Metre will change the default for the `sec` attribute to false here,
but you can override it. Similarly, it will change the default for the `forward` attribute on the domain, since most people
will want components available to external servers - but again, you can change this if you want.

As ever, if you're confused, take a look at the running config in the data directory, and you'll see everything set explicitly.

There's actually code present for connecting to another server as a component - if anyone would find that useful
let me know.

What other transports are supported?
----

All the transports:

* 's2s' - Traditional, DNS-driven, XMPP. DNS records may be overridden, and it can use XEP-0368 if available.
* 'x2x' - XEP-0361 lightweight XMPP, designed for high-latency links such as SATCOM.
* '114' - XEP-0114 Components, for simplified domain-level services. 

I use DNSSEC! What does Metre do?
----

That's great. Metre will:

* Throw away DNS records that are incorrectly [un]signed.
* Use DNSSEC-signed SRV records to gather more reference identifiers for certificates.
* You can also throw away all unsigned records for some server lookups.

To do the latter, add a `dns: dnssec: true` setting to the domain stanza (or `any`
stanza, if you're in an all-DNSSEC environment).

I want to override DNS / my peer doesn't do DNS properly.
----

You can override the SRV, A, and TLSA DNS lookups in the `dns` element. Such overrides
are treated as if they were DNSSEC signed (since we assume your config file is a secure source),
so you can specify `dnssec: true` if you override everything. Note that you'll need to override
both SRV and A records, typically.

```yaml
"no-dns.example.com":
  dns:
    dnssec: true
    srv:
      - host: xmpp-server.example.com
        port: 5290 # Default is 5269
        tls: true # Specify a XEP-0368 record instead.
    host:
     - name: xmpp-server.example.com # Note that the name must match, sorry.
       a: "192.168.0.1"
```

DNS overrides only affect those lookups performed for that domain. Loosely,
the internal API uses the remote domain as context for all lookups.

As a bit of a curve ball, that `a` attribute on `host` can have an IPv6 address in instead
of just IPv4... And the `srv` can have a `tls` attribute giving a boolean of whether it's a
XEP-0368 record or just a traditional one.

Wait... XEP-0368?
----

This is a spec for immediate-mode TLS. Servers lookup `_xmpps-server` and connect to
the result, and instead of using `<starttls/>` they just negotiate TLS straight away. Metre
supports both listening for, and connecting to, XEP-0368 services.

If you want this, you'll need to publish additional SRV records.

You can specify `prefer: direct` or `prefer: starttls` on a `transport` if you want Metre
to put a thumb on the scales of SRV record selection.

I hate CAs! Tell me it does DANE! Please, tell me it does DANE!
----

OK, then. It does DANE, using the (undocumented) offline OpenSSL DANE implementation.

I run a private CA internally and/or my partner organisation doesn't use a CA I recognise.
----

That's fine. Specifying a TLSA record override will work (subject to caveats above). TLSA
records overridden are always used, even if there isn't an (otherwise) secure DNS path
to them. The hostname/port are always ignored (long story, but it's safe), but still need
specifying (which is stupid, probably).

Match data can be given as either a filename (which must contain at least one '/') or as
base64 encoded data, for "Full" matchtype. The file (or data) must be a DER encoded object.

For the two hashes, you can just put the hash in hex form. Colons optional.

```yaml
"shifty.example.com"
  dns:
    tlsa:
     - hostname: shifty.example.com
       port: 5269
       matchtype: Full # Names from RFC
       certusage: TrustAnchorAssertion
       selector: FullCert
       matchdata: ./some-cert.der
```

Note that the moment you have a TLSA override, certificates must pass it. You can have
multiple TLSA records to handle multiple certificates, or rollover - just like normal TLSA
records, only one is required to match. 

Does Metre pass through all traffic unchanged?
----

By default, yes - although the outer stanza element itself is re-rendered.

However, this can change - it's intended to ultimately filter traffic and even respond
to some on behalf of internal servers.

There is limited support for this now, see [FILTERS](FILTERS.md)
