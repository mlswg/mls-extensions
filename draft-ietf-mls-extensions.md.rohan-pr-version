---
title: The Messaging Layer Security (MLS) Extensions
abbrev: MLS
docname: draft-ietf-mls-extensions-latest
category: info

ipr: trust200902
area: Security
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: R. Robert
    name: Raphael Robert
    organization: Phoenix R&D
    email: ietf@raphaelrobert.com

informative:
  mls-protocol:
    target: https://datatracker.ietf.org/doc/draft-ietf-mls-protocol/](https://datatracker.ietf.org/doc/draft-ietf-mls-protocol/
    title: The Messaging Layer Security (MLS) Protocol

  hpke:
    target: https://www.rfc-editor.org/rfc/rfc9180.html](https://www.rfc-editor.org/rfc/rfc9180.html
    title: Hybrid Public Key Encryption

  hpke-security-considerations:
    target: https://www.rfc-editor.org/rfc/rfc9180.html#name-key-compromise-impersonatio](https://www.rfc-editor.org/rfc/rfc9180.html#name-key-compromise-impersonatio
    title: HPKE Security Considerations

--- abstract

This document describes extensions to the Messaging Layer Security (MLS) protocol.

--- middle

# Introduction

This document describes extensions to {{mls-protocol}} that are not part of the
main protocol specification. The protocol specification includes a set of core
extensions that are likely to be useful to many applications. The extensions
described in this document are intended to be used by applications that need to
extend the MLS protocol.

## Change Log

RFC EDITOR PLEASE DELETE THIS SECTION.

draft-03

- Add SelfRemove Proposal

draft-02

- No changes (prevent expiration)

draft-01

- Add Content Advertisement extensions

draft-00

- Initial adoption of draft-robert-mls-protocol-00 as a WG item.
- Add Targeted Messages extension (\*)

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

## Targeted messages

### Description

MLS application messages make sending encrypted messages to all group members
easy and efficient. Sometimes application protocols mandate that messages are
only sent to specific group members, either for privacy or for efficiency
reasons.

Targeted messages are a way to achieve this without having to create a new group
with the sender and the specific recipients – which might not be possible or
desired. Instead, targeted messages define the format and encryption of a
message that is sent from a member of an existing group to another member of
that group.

The goal is to provide a one-shot messaging mechanism that provides
confidentiality and authentication.

Targeted Messages reuse mechanisms from {{mls-protocol}}, in particular {{hpke}}.

### Format

This extensions introduces a new message type to the MLS protocol,
`TargetedMessage` in `WireFormat` and `MLSMessage`:

~~~ tls
enum {
  ...
  mls_targeted_message(6),
  ...
  (255)
} WireFormat;

struct {
    ProtocolVersion version = mls10;
    WireFormat wire_format;
    select (MLSMessage.wire_format) {
        ...
        case mls_targeted_message:
            TargetedMessage targeted_message;
    }
} MLSMessage;
~~~

The `TargetedMessage` message type is defined as follows:

~~~ tls
struct {
  opaque group_id<V>;
  uint64 epoch;
  uint32 recipient_leaf_index;
  opaque authenticated_data<V>;
  opaque encrypted_sender_auth_data<V>;
  opaque hpke_ciphertext<V>;
} TargetedMessage;

enum {
  hpke_auth_psk(0),
  signature_hpke_psk(1),
} TargetedMessageAuthScheme;

struct {
  uint32 sender_leaf_index;
  TargetedMessageAuthScheme authentication_scheme;
  select (authentication_scheme) {
    case HPKEAuthPsk:
    case SignatureHPKEPsk:
      opaque signature<V>;
  }
  opaque kem_output<V>;
} TargetedMessageSenderAuthData;

struct {
  opaque group_id<V>;
  uint64 epoch;
  uint32 recipient_leaf_index;
  opaque authenticated_data<V>;
  TargetedMessageSenderAuthData sender_auth_data;
} TargetedMessageTBM;

struct {
  opaque group_id<V>;
  uint64 epoch;
  uint32 recipient_leaf_index;
  opaque authenticated_data<V>;
  uint32 sender_leaf_index;
  TargetedMessageAuthScheme authentication_scheme;
  opaque kem_output<V>;
  opaque hpke_ciphertext<V>;
} TargetedMessageTBS;

struct {
  opaque group_id<V>;
  uint64 epoch;
  opaque label<V> = "MLS 1.0 targeted message psk";
} PSKId;
~~~

Note that `TargetedMessageTBS` is only used with the
`TargetedMessageAuthScheme.SignatureHPKEPsk` authentication mode.

### Encryption

Targeted messages use HPKE to encrypt the message content between two leaves.
The HPKE keys of the `LeafNode` are used to that effect, namely the
`encryption_key` field.

In addition, `TargetedMessageSenderAuthData` is encrypted in a similar way to
`MLSSenderData` as described in section 7.3.2 in {{mls-protocol}}. The
`TargetedMessageSenderAuthData.sender_leaf_index` field is the leaf index of the
sender. The `TargetedMessageSenderAuthData.authentication_scheme` field is the
authentication scheme used to authenticate the sender. The
`TargetedMessageSenderAuthData.signature` field is the signature of the
`TargetedMessageTBS` structure. The `TargetedMessageSenderAuthData.kem_output`
field is the KEM output of the HPKE encryption.

The key and nonce provided to the AEAD are computed as the KDF of the first
KDF.Nh bytes of the `hpke_ciphertext` generated in the following section. If the
length of the hpke_ciphertext is less than KDF.Nh, the whole hpke_ciphertext is
used. In pseudocode, the key and nonce are derived as:

~~~
sender_auth_data_secret
  = MLS-Exporter("targeted message sender auth data", "", KDF.Nh)

ciphertext_sample = hpke_ciphertext[0..KDF.Nh-1]

sender_data_key = ExpandWithLabel(sender_auth_data_secret, "key",
                      ciphertext_sample, AEAD.Nk)
sender_data_nonce = ExpandWithLabel(sender_auth_data_secret, "nonce",
                      ciphertext_sample, AEAD.Nn)
~~~

The Additional Authenticated Data (AAD) for the `SenderAuthData` ciphertext is
the first three fields of `TargetedMessage`:

~~~
struct {
  opaque group_id<V>;
  uint64 epoch;
  uint32 recipient_leaf_index;
} SenderAuthDataAAD;
~~~

#### Padding

The `TargetedMessage` structure does not include a padding field. It is the
responsibility of the sender to add padding to the `message` as used in the next
section.

### Authentication

For ciphersuites that support it, HPKE `mode_auth_psk` is used for
authentication. For other ciphersuites, HPKE `mode_psk` is used along with a
signature. The authentication scheme is indicated by the `authentication_scheme`
field in `TargetedMessageContent`. See {{guidance-on-authentication-schemes}}
for more information.

For the PSK part of the authentication, clients export a dedicated secret:

~~~
targeted_message_psk = MLS-Exporter("targeted message psk", "", KDF.Nh)
~~~

Th functions `SealAuth` and `OpenAuth` are defined in {{hpke}}. Other functions
are defined in {{mls-protocol}}.

#### Authentication with HPKE

The sender MUST set the authentication scheme to
`TargetedMessageAuthScheme.HPKEAuthPsk`.

The sender then computes the following:

~~~
(kem_output, hpke_ciphertext) = SealAuthPSK(receiver_node_public_key,
                                            group_context,
                                            targeted_message_tbm,
                                            message,
                                            targeted_message_psk,
                                            psk_id,
                                            sender_node_private_key)
~~~

The recipient computes the following:

~~~
message = OpenAuthPSK(kem_output,
                      receiver_node_private_key,
                      group_context,
                      targeted_message_tbm,
                      hpke_ciphertext,
                      targeted_message_psk,
                      psk_id,
                      sender_node_public_key)
~~~

#### Authentication with signatures

The sender MUST set the authentication scheme to
`TargetedMessageAuthScheme.SignatureHPKEPsk`. The signature is done using the
`signature_key` of the sender's `LeafNode` and the corresponding signature
scheme used in the group.

The sender then computes the following:

~~~
(kem_output, hpke_ciphertext) = SealPSK(receiver_node_public_key,
                                        group_context,
                                        targeted_message_tbm,
                                        message,
                                        targeted_message_psk,
                                        epoch)

signature = SignWithLabel(., "TargetedMessageTBS", targeted_message_tbs)
~~~

The recipient computes the following:

~~~
message = OpenPSK(kem_output,
                  receiver_node_private_key,
                  group_context,
                  targeted_message_tbm,
                  hpke_ciphertext,
                  targeted_message_psk,
                  epoch)
~~~

The recipient MUST verify the message authentication:

~~~
VerifyWithLabel.verify(sender_leaf_node.signature_key,
                        "TargetedMessageTBS",
                        targeted_message_tbs,
                        signature)
~~~

### Guidance on authentication schemes

If the group’s ciphersuite does not support HPKE `mode_auth_psk`,
implementations MUST choose `TargetedMessageAuthScheme.SignatureHPKEPsk`.

If the group’s ciphersuite does support HPKE `mode_auth_psk`, implementations
CAN choose `TargetedMessageAuthScheme.HPKEAuthPsk` if better efficiency and/or
repudiability is desired. Implementations SHOULD consult
{{hpke-security-considerations}} beforehand.

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

## SelfRemove Proposal

The design of the MLS protocol prevents a member of
an MLS group from removing itself immediately from the group. To cause
an immediate change in the group, a member must send a Commit message.
However the sender of a Commit message knows the keying material of the
new epoch and therefore needs to be part of the group. Instead a member
wishing to remove itself can send a Remove Proposal and wait for another
member to Commit its Proposal.

Unfortunately, MLS clients that join via an External Commit ignore
pending, but otherwise valid, Remove Proposals. The member trying to remove itself has
to monitor the group and send a new Remove Proposal in any new epoch until the member is
removed. In a
group with a burst of external joiners, a member connected over a
high-latency link (or one that is merely unlucky) might have to wait
several epochs to remove itself. A real-world situation in which this happens
is a member trying to remove itself from a conference call as several dozen
new participants are trying to join (often on the hour).

This section describes a new `SelfRemove` Proposal extension type. It is
designed to be included in External Commits.

### Extension Description

This document specifies a new MLS Proposal type called `SelfRemove`. Its syntax
is described using the TLS Presentation Language [@!RFC8446] below (its contents
is an empty struct). It is allowed in External Commits and requires an UpdatePath.
SelfRemove proposals are only allowed in a Commit by reference. SelfRemove
cannot be sent as an external proposal.

~~~ tls-presentation
struct {} SelfRemove;

struct {
    ProposalType msg_type;
    select (Proposal.msg_type) {
        case add:                      Add;
        case update:                   Update;
        case remove:                   Remove;
        case psk:                      PreSharedKey;
        case reinit:                   ReInit;
        case external_init:            ExternalInit;
        case group_context_extensions: GroupContextExtensions;
        case self_remove:              SelfRemove;
    };
} Proposal;
~~~

The description of behavior below only applies if all the
members of a group support this extension in their
capabilities; such a group is a "self-remove-capable group".

An MLS client which implements this specification can send a
SelfRemove Proposal whenever it would like to remove itself
from a self-remove-capable group. Because the point of a
SelfRemove Proposal is to be available to external joiners
(which are not yet members), these proposals MUST be sent
as an MLS PublicMessage.

Whenever a member receives a SelfRemove Proposal, it includes
it along with any other pending Propsals when sending a Commit.
It already MUST send a Commit of pending Proposals before sending
new application messages.

When a member receives a Commit with an embedded SelfRemove Proposal,
it treats the proposal like a Remove Proposal, except the leaf node to remove
is determined by looking in the Sender `leaf_index` of the original Proposal.
The member is able to verify that the Sender was a member.

Whenever a new joiner is about to join a self-remove-capable group with an
External Commit, the new joiner MUST fetch any pending SelfRemove Proposals
along with the GroupInfo object, and include the SelfRemove Proposals
in its External Commit by reference. (An ExternalCommit can contain zero or
more SelfRemove proposals). The new joiner validates the SelfRemove
Proposal before including it by reference, except that it skips the validation
of the `membership_tag` because a non-member cannot verify membership.

During validation, SelfRemove proposals are processed after Update proposals
and before Remove proposals. If there is a pending SelfRemove proposal for a specific
leaf node and a pending Remove proposal for the same leaf node, the Remove proposal is
invalid. A client MUST NOT issue more than one SelfRemove proposal per epoch.

The MLS Distribution Service (DS) needs to validate SelfRemove Proposals it
receives (except that it cannot validate the `membership_tag`). If the DS
provides a GroupInfo object to an external joiner, the DS SHOULD attach any
SelfRemove proposals known to the DS to the GroupInfo object.

As with Remove proposals, clients need to be prepared to receive the Commit
message which removes them from the group via a SelfRemove. If the DS does
not forward a Commit to a removed client, it needs to inform the removed
client out-of-band.

# IANA Considerations

This document requests the addition of various new values under the heading
of "Messaging Layer Security".  Each registration is organized under the
relevant registry Type.

RFC EDITOR: Please replace XXXX throughout with the RFC number assigned to
this document

## MLS Wire Formats

### Targeted Messages wire format

 * Value: 0x0006
 * Name: * Name: mls_targeted_message
 * Recommended: Y
 * Reference: RFC XXXX

## MLS Extension Types

### targeted_messages_capability MLS Extension

The `targeted_messages_capability` MLS Extension Type is used in the
capabilities field of LeafNodes to indicate the support for the Targeted
Messages Extension. The extension does not carry any payload.

* Value: 0x0006
* Name: targeted_messages_capability
* Message(s): LN: This extension may appear in LeafNode objects
* Recommended: Y
* Reference: RFC XXXX

### targeted_messages MLS Extension

The `targeted_messages` MLS Extension Type is used inside GroupContext objects. It
indicates that the group supports the Targeted Messages Extension.

* Value: 0x0007
* Name: targeted_messages
* Message(s): GC: This extension may appear in GroupContext objects
* Recommended: Y
* Reference: RFC XXXX

### accepted_media_types MLS Extension

The `accepted_media_types` MLS Extension Type is used inside LeafNode objects. It
contains a MediaTypeList representing all the media types supported by the
MLS client referred to by the LeafNode.

* Value: 0x0008
* Name: accepted_media_types
* Message(s): LN: This extension may appear in LeafNode objects
* Recommended: Y
* Reference: RFC XXXX

### required_media_types MLS Extension

The required_media_types MLS Extension Type is used inside GroupContext objects. It
contains a MediaTypeList representing the media types which are mandatory for all
MLS members of the group to support.

* Value: 0x0009
* Name: required_media_types
* Message(s): GC: This extension may appear in GroupContext objects
* Recommended: Y
* Reference: RFC XXXX

## MLS Proposal Types

### AppAck Proposal

* Value: 0x0008
* Name: app_ack
* Recommended: Y
* Path Required: Y
* Reference: RFC XXXX

### SelfRemove Proposal

The `self_remove` MLS Proposal Type is used for a member to remove itself
from a group more efficiently than using a `remove` proposal type, as the
`self_remove` type is permitted in External Commits.

* Value: 0x0009
* Name: self_remove
* Recommended: Y
* External: N
* Path Required: Y
* Reference: RFC XXXX

# Security considerations

## AppAck

TBC

## Targeted Messages

In addition to the sender authentication, Targeted Messages are authenticated by
using a preshared key (PSK) between the sender and the recipient. The PSK is
exported from the group key schedule using the label "targeted message psk".
This ensures that the PSK is only valid for a specific group and epoch, and the
Forward Secrecy and Post-Compromise Security guarantees of the group key
schedule apply to the targeted messages as well. The PSK also ensures that an
attacker needs access to the private group state in addition to the
HPKE/signature's private keys. This improves confidentiality guarantees against
passive attackers and authentication guarantees against active attackers.

## Content Advertisement

Use of the `accepted_media_types` and `rejected_media_types` extensions
could leak some private information visible in KeyPackages and inside an MLS group.
They could be used to infer a specific implementation, platform, or even version.
Clients should consider carefully the privacy implications in their environment of
making a list of acceptable media types available.

## SelfRemove

An external recipient of a SelfRemove Proposal cannot verify the
`membership_tag`. However, an external joiner also has no way to
completely validate a GroupInfo object that it receives. An insider
can prevent an External Join by providing either an invalid GroupInfo object
or an invalid SelfRemove Proposal. The security properties of external joins
does not change with the addition of this proposal type.

# Contributors

The `accepted_media_types` and `rejected_media_types` extensions, and the
SelfRemove Proposal extension were written by Rohan Mahy.
