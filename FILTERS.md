# Filters

Filters in Metre are named, long-lived, stateful objects which have one instance per domain.

Filters (currently) operate on stanzas when they are inbound on a stream - stanzas
generated internally and routed directly out are therefore not (currently) subject to filters.

A stanza coming from from.example and addressed to to.example arriving on a stream from from.example to to.example passes through each defined filter for from.example in sequence, and then each defined filter for to.example.

Each filter can DROP the stanza entirely, PASS it through unchanged, or mutate it. (If they choose to mutate it, they need to be careful to keep string data live).

Filters may have global configuration, within the `filters` key inside the `globals` section,
and must have per-domain configuration within the domain's `filter-in` section. (The YAML shorthand of `~` can be useful if you don't have anything to configure). Ordering
is significant here, since filters are applied in order.

## Example

```yaml
global:
  filters:
    megafilter:
      froobisciousness: high

remote:
  from.example:
    # ...
    filter-in:
      megafilter: ~
      otherfilter:
        vegetable: potato
        magic: classical
local:
  to.example:
    filter-in:
      otherfilter:
        vegetable: tomato

```

Here, from.example has two filters:
* `megafilter`, which has no domain-specific configuration (but does have some global configuration, since the default level of froobisciousness is clearly unacceptable).
* `otherfilter`, which has no global config (or if it does, it's all defaults), but does have domain-specific vegetable selection and has switched the magical paradigm to classical (since quantum magic is relatively unpredictable).

`to.example` just has the `otherfilter` defined; the existence of the global `megafilter` configuration doesn't affect this at all.

In this instance, a stanza arriving on a stream from from.example to to.example will pass through the following:

* FILTER_DIRECTION::IN from.example megafilter
* FILTER_DIRECTION::IN from.example otherfilter
* FILTER_DIRECTION::OUT to.example otherfilter

## Writing Filters

Many custom deployments of Metre have a custom filter. To write one, the minimum required is:

* Derive a class from `::Metre::Filter`
* Add a subclass of `Description`, publicly inheriting from `::Metre::Filter::Description<YourFilter>`. Descriptions are both a Factory concept and also hold your global configuration.
  * If you need global config, override the `void config(YAML::Node const & config) override` method, and also
  * dump your config back out like a good citizen with `void do_config(YAML::Node & config) override`.
* Add a constructor taking (::Metre::Filter::BaseDescription & base, Config::Domain & domain, YAML::Node const & config);
  * base should be passed to the Filter constructor. This will end up as m_description
  * domain is the Config::Domain object for your configured domain.
  * config is the filter-in YAML object with your configuration in.
* Define the apply coroutine method.
* If you have any per-domain configuration, write it back out in `void do_dump_config(YAML::Node & config) override`

Inside the apply function, you can access the Stanza's XML via stanza.node(), and mutate it to your heart's content, but be wary of rapidxml, which will not take copies of strings. So:

* Add nodes by allocating within rapidxml; either node->append_element or node->document()->allocate_node
* Allocate attributes with node->document()->allocate_attribute
* String values must be:
  * Character literals, like `"..."` (since pointers to these are stable)
  * Allocated with the document, as node->document()->allocate_string
  * If you are feeling brave, or wildly overconfident: String data which remains in scope, such as from configuration values or direct copies from other data within the stanza (but be very wary of intermediate copies)
* If for some reason you can't do this, then it's always safe (and inefficient) to `s.freeze()`, which will duplicate and reallocate the entire stanza's XML internally.

As a general rule, though, literals or allocate_string and you'll be fine.

If you write something useful that could be open sourced, please do pass it upstream and I'll try to include it.

## Existing Filters

The only existing (working) filter is the disco-cache filter. It is a non-mutating filter which intercepts
and caches disco responses from clients (which themselves do not change) and intercepts and
responds to those disco requests to nodes it has cached.

This allows a surprising amount of redundant queries to be elided over S2S links, which can help with bandwidth management.

There is no special per-domain configuration, and no global configuration at all.
