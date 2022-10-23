---
title: The Messaging Layer Security (MLS) Extensions
abbrev: MLS
docname: draft-robert-mls-extensions-latest
category: info

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: R. Robert
    name: Raphael Robert
    organization:
    email: ietf@raphaelrobert.com

--- abstract

This document describes extensions to the Messaging Layer Security (MLS) protocol.

--- middle

# Introduction

This document describes extensions to the Messaging Layer Security (MLS)
protocol that are not part of the main protocol specification. The protocol
specification includes a set of core extensions that are likely to be useful to
many applications. The extensions described in this document are intended to be
used by applications that need to extend the MLS protocol.

# Extensions

## AppAck

Type: Proposal

### Description

An AppAck proposal is used to acknowledge receipt of application messages.
Though this information implies no change to the group, it is structured as a
Proposal message so that it is included in the group's transcript by being
included in Commit messages.

~~~ tls
struct {
    uint32 sender;
    uint32 first_generation;
    uint32 last_generation;
} MessageRange;

struct {
    MessageRange received_ranges<V>;
} AppAck;
~~~

An AppAck proposal represents a set of messages received by the sender in the
current epoch.  Messages are represented by the `sender` and `generation` values
in the MLSCiphertext for the message.  Each MessageRange represents receipt of a
span of messages whose `generation` values form a continuous range from
`first_generation` to `last_generation`, inclusive.

AppAck proposals are sent as a guard against the Delivery Service dropping
application messages.  The sequential nature of the `generation` field provides
a degree of loss detection, since gaps in the `generation` sequence indicate
dropped messages.  AppAck completes this story by addressing the scenario where
the Delivery Service drops all messages after a certain point, so that a later
generation is never observed.  Obviously, there is a risk that AppAck messages
could be suppressed as well, but their inclusion in the transcript means that if
they are suppressed then the group cannot advance at all.

The schedule on which sending AppAck proposals are sent is up to the application,
and determines which cases of loss/suppression are detected.  For example:

* The application might have the committer include an AppAck proposal whenever a
  Commit is sent, so that other members could know when one of their messages
  did not reach the committer.

* The application could have a client send an AppAck whenever an application
  message is sent, covering all messages received since its last AppAck.  This
  would provide a complete view of any losses experienced by active members.

* The application could simply have clients send AppAck proposals on a timer, so
  that all participants' state would be known.

An application using AppAck proposals to guard against loss/suppression of
application messages also needs to ensure that AppAck messages and the Commits
that reference them are not dropped.  One way to do this is to always encrypt
Proposal and Commit messages, to make it more difficult for the Delivery Service
to recognize which messages contain AppAcks.  The application can also have
clients enforce an AppAck schedule, reporting loss if an AppAck is not received
at the expected time.

## Content Advertisement

### Description

This section describes two extensions to MLS. The first allows MLS clients
to advertise their support for specific formats inside MLS `application_data`.
These are expressed using the extensive IANA Media Types registry (formerly
called MIME Types).  The `accepted_media_types` LeafNode extension lists the
formats a client supports inside `application_data`. The second, the
`required_media_types` GroupContext extension specifies which media types
need to be supported by all members of a particular MLS group.
These allow clients to confirm that all members of a group can communicate.
Note that when the membership of a group changes, or when the policy of the
group changes, it is responsibility of the committer to insure that the membership
and policies are compatible.

Finally, this document defines a minimal framing format so MLS clients can signal
which media type is being sent when multiple formats are permitted in the same group.
As clients are upgraded to support new formats they can use these extensions
to detect when all members support a new or more efficient encoding, or select the
relevant format or formats to send.

Note that the usage of IANA media types in general does not imply the usage of MIME
Headers {{?RFC2045}} for framing. Vendor-specific media subtypes starting with
`vnd.` can be registered with IANA without standards action as described in
{{?RFC6838}}.  Implementations which wish to send multiple formats in a single
application message, may be interested in the `multipart/alternative` media type
defined in {{?RFC2046}} or may use or define another type with similar semantics
(for example using TLS Presentation Language syntax {{!RFC8446}}).

### Syntax

MediaType is a TLS encoding of a single IANA media type (including top-level
type and subtype) and any of its parameters. Even if the `parameter_value`
would have required formatting as a `quoted-string` in a text encoding, only
the contents inside the `quoted-string` are included in `parameter_value`.
MediaTypeList is an ordered list of MediaType objects.

~~~ tls
struct {
    opaque parameter_name<V>;
    /* Note: parameter_value never includes the quotation marks of an
     * RFC 2045 quoted-string */
    opaque parameter_value<V>;
} Parameter;

struct {
    /* media_type is an IANA top-level media type, a "/" character,
     * and the IANA media subtype */
    opaque media_type<V>;

    /* a list of zero or more parameters defined for the subtype */
    Parameter parameters<V>;
} MediaType;

struct {
    MediaType media_types<V>;
} MediaTypeList;

MediaTypeList accepted_media_types;
MediaTypeList required_media_types;
~~~

Example IANA media types with optional parameters:

~~~ artwork
  image/png
  text/plain ;charset="UTF-8"
  application/json
  application/vnd.example.msgbus+cbor
~~~

For the example media type for `text/plain`, the `media_type` field
would be `text/plain`, `parameters` would contain a single Parameter
with a `parameter_name` of `charset` and a `parameter_value` of `UTF-8`.

### Expected Behavior

An MLS client which implements this section SHOULD include the
`accepted_media_types` extension in its LeafNodes, listing
all the media types it can receive. As usual, the
client also includes `accepted_media_types` in its `capabilities` field in
its LeafNodes (including LeafNodes inside its KeyPackages).

When creating a new MLS group for an application using this specification,
the group MAY include a `required_media_type` extension in the GroupContext
Extensions. As usual, the client also includes
`required_media_types` in its `capabilities` field in its LeafNodes
(including LeafNodes inside its KeyPackages). When used in a group, the client
MUST include the `required_media_types` and `accepted_media_types` extensions
in the list of extensions in RequiredCapabilities.

MLS clients SHOULD NOT add an MLS client to an MLS group with `required_media_types`
unless the MLS client advertises it can support all of the required MediaTypes.
As an exception, a client could be preconfigured to know that certain clients
support the requried types. Likewise, an MLS client is already forbidden from
issuing or committing a GroupContextExtensions Proposal which introduces required
extensions which are not supported by all members in the resulting epoch.


### Framing of application_data

When an MLS group contains the `required_media_types` GroupContext extension,
the `application_data` sent in that group is interpreted as `ApplicationFraming`
as defined below:

~~~ tls
  struct {
      MediaType media_type;
      opaque<V> application_content;
  } ApplicationFraming;
~~~

The `media_type` MAY be zero length, in which case, the media type of the
`application_content` is interpreted as the first MediaType specified in
`required_media_types`.

# IANA Considerations

This document requests the creation of the following new IANA registries:

* MLS Extension Types ({{extended-mls-extension-types}})
* MLS Proposal Types ({{extended-mls-proposal-types}})

All of these registries should be under a heading of "Messaging Layer Security",
and assignments are made via the Specification Required policy {{!RFC8126}}.

RFC EDITOR: Please replace XXXX throughout with the RFC number assigned to
this document

## MLS Extension Type

## accepted_media_types MLS Extension Type

The `accepted_media_types` MLS Extension Type is used inside LeafNode objects. It
contains a MediaTypeList representing all the media types supported by the
MLS client referred to by the LeafNode.

~~~~~~~~
  Template:
  Value: 0x0005
  Name: accepted_media_types
  Message(s): This extension may appear in LeafNode objects
  Recommended: Y
  Reference: RFC XXXX
~~~~~~~~


## required_media_types MLS Extension Type

The required_media_types MLS Extension Type is used inside GroupContext objects. It
contains a MediaTypeList representing the media types which are mandatory for all
MLS members of the group to support.

~~~~~~~~
  Template:
  Value: 0x0006
  Name: required_media_types
  Message(s): This extension may appear in GroupContext objects
  Recommended: Y
  Reference: RFC XXXX
~~~~~~~~


## Extended MLS Extension types

This registry lists identifiers for extensions to the MLS protocol.  The
extension type field is two bytes wide, so valid extension type values are in
the range 0x0000 to 0xffff.

Template:

* Value: The numeric value of the extension type. Extended MLS extension types
  start with the value 0x0100.

* Name: The name of the extension type

* Message(s): The messages in which the extension may appear, drawn from the following
  list:

  * KP: KeyPackage objects
  * LN: LeafNode objects
  * GC: GroupContext objects (and the `group_context_extensions` field of
    GroupInfo objects)
  * GI: The `other_extensions` field of GroupInfo objects

* Recommended: Whether support for this extension is recommended by the IETF MLS
  WG.  Valid values are "Y" and "N".  The "Recommended" column is assigned a
  value of "N" unless explicitly requested, and adding a value with a
  "Recommended" value of "Y" requires Standards Action [RFC8126].  IESG Approval
  is REQUIRED for a Y->N transition.

* Reference: The document where this extension is defined

Initial contents:

| Value            | Name                     | Message(s) | Recommended | Reference |
|:-----------------|:-------------------------|:-----------|:------------|:----------|
| N/A              | N/A                      | N/A        | N/A         | RFC XXXX  |

## Extended MLS Proposal types

This registry lists identifiers for types of proposals that can be made for
changes to an MLS group.  The extension type field is two bytes wide, so valid
extension type values are in the range 0x0000 to 0xffff.

Template:

* Value: The numeric value of the proposal type. Extended MLS proposal types start
  with the value 0x0100.
* Name: The name of the proposal type
* Recommended: Whether support for this extension is recommended by the IETF MLS
  WG.  Valid values are "Y" and "N".  The "Recommended" column is assigned a
  value of "N" unless explicitly requested, and adding a value with a
  "Recommended" value of "Y" requires Standards Action [RFC8126].  IESG Approval
  is REQUIRED for a Y->N transition.
* Path Required: Whether a Commit covering a proposal of this type is required
  to have its `path` field populated.
* Reference: The document where this extension is defined

Initial contents:

| Value            | Name                     | Recommended | Path Required | Reference |
|:-----------------|:-------------------------|:------------|:--------------|:----------|
| 0x0100           | app_ack                  | Y           | Y             | RFC XXXX  |

# Security Consideration

## Content Advertisement

Use of the `accepted_media_types` and `rejected_media_types` extensions
could leak some private information visible in KeyPackages and inside an MLS group.
They could be used to infer a specific implementation, platform, or even version.
Clients should consider carefully the privacy implications in their environment of
making a list of acceptable media types available.

# Contributors

The `accepted_media_types` and `rejected_media_types` extensions were written
by Rohan Mahy.
