Metre FAQ
==========

Why not call it Meter?
-----

Metre is the right spelling. It's also the form typically used (even in US English) for poetry,
and XMPP often uses poetry terms (like stanza).

Who is "I"?
----

I am Dave Cridland. You can find me in various places. If you're using Metre, or interested in doing so,
drop me a line, or an IM, or whatever.

Is this an XMPP server?
----

Well... Sort of. You can't connect clients to it, only servers and components (which are
sort of servers anyway). It can offer services - but it actually only provides XEP-0199
ping responses which are useful for diagnostics and testing. I might add version.

What it's for is for hosting components outside of a full server, and for letting two
servers which cannot talk to each other directly connect through it "back to back".

So if you have a number of internal services which cannot be exposed, or cannot perform
the required security, you can have those setup as "forwarded" domains, and Metre will respond
to other, non-forwarded domains pretending to be them. As an example, if you want to expose
your service `example.com` to the world, but you don't want to risk having it directly accessible,
then you'd put Metre in your DMZ, have `example.com` connect to it, instead of the internet,
and then the world will connect to Metre.

Metre does need your TLS certificate and private key, however. Something like:

Example:

```xml
<remote>
  <domain name='example.com' forward='true'>
    <!-- Connect by low security: -->
    <transport type='s2s' sec='false'>
      <auth type='dialback'/>
    </transport>
    <ciphers>DEFAULT</ciphers>
    <dhparam size='1024'/>
    <!-- Use this X.509 identity -->
    <x509 chain='chain-file.pem' pkey='keyfile.pem'/>
  </domain>
  <any>
    <transport type='s2s'/>
  </any>
</remote>
```

How production-ready is this?
----

I would describe this as:

* MVP - it's not doing as much as I'd like, but it's essentially useful in its current form.
* Beta - while it seems to work well enough for non-critical deployments, operational experience is lacking.

Does it score OK on the IM Observatory?
----

It can get an A without much effort; the defaults are designed around this. 

* I'm connecting a Java server and...

Java, until recently, couldn't handle reasonable DH parameters used for Perfect
Forward Secrecy, and would choke.

Even now, you'll need to lower DH parameter sizes for that server - you can do this
with either `<dhparam size='1024'/>` or `<dhparam size='2048'/>` (for Java7 and Java8)
within the `<domain/>` stanza for the Java server. Metre picks the DH parameter size
based on the minimum of the requested, and the minimum configured size. Allowable
sizes are 1024, 2048 and 4096 - the latter si the default.

Frustratingly, servers ask for low keylengths by default - OpenSSL asks for 1024, for
example, even when it will cheerfully support higher.

Example:

```xml
  <domain name='tigase.example.com'>
    <dhparam size='1024'/>
  </domain>
```

My internal server only supports 3DES...
----

Just as with DH parameters, you can change the cipher suites as well for certain servers.

Just change the `<ciphers/>` directive to allow the ciphers you need. It's a traditional OpenSSL cipher list.

The default is (currently) HIGH:!3DES:!aNULL:!eNULL:@STRENGTH

Example:

```xml
  <domain name='ms-dos.example.com'>
    <ciphers>DEFAULT</ciphers><!-- Use OpenSSL defaults -->
  </domain>
```

I'm trying to connect to a domain hosted on Google, and ...
----

Google's broken GTalk service is largely unmaintained, and never supported any kind
of TLS. Metre requires TLS by default, but you can change that within the transport definition
by adding a `sec='false'` attribute to the transport. You'll almos certainly want to enable
dialback for these.

Example:

```xml
  <domain name='google.example.com'>
    <transport type='s2s' sec='false'><!-- Don't require a secure transport -->
     <auth type='dialback'/>
    </transport>
  </domain>
```

When does a config item get used?
----

Some are inbound, some are outbound, and some are confusing.

`<dhparam/>`, `<ciphers/>`, and `<transport/>` are all based on the remote server. So in the examples above,
google.example.com will be expected to be over S2S, with optional TLS, ms-dos.example.com will
have basic ciphers, and so on.

In particular, the authentication methods (pkix, dialback, and secret) are how Metre will
authenticate the remote domain, and not how it will authenticate itself *to* the remote domain.

However the `<509/>` identity is how Metre will behave for the domain when it's hosting it, and not what it'll
be using when connecting remotely.

How are XEP-0114 components hosted?
----

XEP-0114 components are, to Metre, just another kind of remote server, albeit one it
cannot initiate a connection to. The difference is that you'll need to define the `<transport/>` type as "114",
and set a secret for the authentication with a child element of `<auth type='secret'/>`, like so:

```xml
<domain name='component.example.com'>
  <transport type='114'>
     <auth type='secret'>S3Kr3T!</auth>
  </transport>
</domain>
```

Most component libraries will not negotiate TLS, so Metre will change the default for the `sec` attribute to false here,
but you can override it. Similarly, it will change the default for the `forward` attribute on the domain, since most people
will want components available to external servers - but you can change this if you want.

I use DNSSEC! What does Metre do?
----

That's great. DNSSEC support in Metre is fairly slim, currently. It will:

* Throw away DNS records that are incorrectly [un]signed.
* You can also throw away all unsigned records for some server lookups.

To do the latter, add a `<dns dnssec='true'/>` element to the domain stanza (or any
stanza, if you're in an all-DNSSEC environment).

Does Metre pass through all traffic unchanged?
----

Currently, yes - although the outer stanza element itself is re-rendered.

However, this will change - it's intended to ultimately filter traffic and even respond
to some on behalf of internal servers.