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

## Message Streams

### Description

By default, for each leaf node, [MLS defines](https://www.rfc-editor.org/rfc/rfc9420.html#section-9-5.1.1) two symmetric hash ratchets. One is used for handshake messages, and the other is used for application messages.

Some applications may require more than one application message ratchet. For example, an application may want to send messages with different delivery semantics or different policies. This section describes an extension to MLS which allows MLS clients to send multiple types of messages. Each message type has it's own independent key ratchet.

**Note: ** Applications which do not require different delivery semantics or policies for different messages SHOULD NOT use this extension. Instead, applicatons MAY simply specify different message types within the standard MLS application messages. // TODO improve wording

### Format

This extension introduces a new message type to the MLS protocol, `MSApplicationMessage` in `WireFormat` and `MLSMessage`:

~~~ tls
enum {
    ...
    mls_ms_application_message(7),
    ...
    (255)
} WireFormat;

struct {
    ProtocolVersion version = mls10;
    WireFormat wire_format;
    select (MLSMessage.wire_format) {
        ...
        case mls_ms_application_message:
            MSApplicationMessage application_message;
    }
} MLSMessage;
~~~

The `MSApplicationMessage` struct is defined as follows:

~~~ tls
struct {
    opaque group_id<V>;
    uint64 epoch;
    uint16 stream_id;
    opaque authenticated_data<V>;
    opaque encrypted_sender_data<V>;
    opaque ciphertext<V>;
} MSApplicationMessage;
~~~

`encrypted_sender_data` and `ciphertext` are encrypted using the AEAD function specified by the cipher suite in use, using the SenderData and MSPrivateMessageContent structures as input.

The `MSPrivateMessageContent` struct is defined as follows:

~~~ tls
struct {
    opaque application_data<V>;
    FramedContentAuthData auth;
    opaque padding[length_of_padding];
} MSPrivateMessageContent;
~~~

MSApplicationMessage and MSPrivateMessageContent are identical to the standard MLS PrivateMessage and PrivateMessageContent and should be treated as such with the following exceptions:

- MSApplicationMessage does not have a `content_type` field. The content type is always `application` as only application messages are supported by this extension.
- MSApplicationMessage has a `stream_id` field. This field is a 16-bit unsigned integer which identifies the message stream to which this message belongs. When decrypting the `ciphertext`, the MLS client MUST use the key ratchet associated with the message stream identified by `stream_id`.
- When decoding a `MSApplicationMessage`, the MLS client MUST verify that the `stream_id` is valid for the group. If the `stream_id` is not valid, the MLS client MUST discard the message.

### Key Schedule

This extension introduces a new secret.

| Label | Secret | Purpose |
|:------|:-------|:--------|
| "ms encryption" | `ms_encryption_secret` | Derived message stream message encryption keys (via the secret tree) |

A secret tree is computed as seen in [Figure 25](https://www.rfc-editor.org/rfc/rfc9420.html#section-9-3.1.1), however the root secret is `ms_encryption_secret` instead of `encryption_secret`.

The secret in the leaf of the secret tree is used to initiate `num_streams` symmetric hash ratchets, from which a sequence of single-use keys and nonces are derived, as described in Section 9.1. The root of each ratchet is computed as:

~~~
tree_node_[N]_secret
|
|
+--> ExpandWithLabel(., "message_stream_[I]", "", KDF.Nh)
|    = ms_ratchet_secret_[I]_[N]_[0]
~~~

where `I` is the message stream index.

#### GroupContext & LeafNode Extension

This extension defines a new GroupContext extension type, `message_streams`. The `extension_data` field of this extension is a `MessageStreamExtension` object.

~~~ tls
struct {
    uint16 num_streams;
} MessageStreamExtension;
~~~

The `num_streams` field is a 16-bit unsigned integer indicating the number of message streams in the group.



# IANA Considerations

This document requests the addition of various new values under the heading
of "Messaging Layer Security".  Each registration is organized under the
relevant registry Type.

RFC EDITOR: Please replace XXXX throughout with the RFC number assigned to
this document

## MLS Wire Formats

### Targeted Messages wire format

 * Value: 0x0006
 * Name: mls_targeted_message
 * Recommended: Y
 * Reference: RFC XXXX

### Message Streams wire format

 * Value: 0x0007
 * Name: mls_ms_application_message
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

### message_streams MLS Extension

The `message_streams` MLS Extension Type is used inside GroupContext objects. It contains a MessageStreamExtension object representing the number of message streams.

* Value: 0x0010
* Name: message_streams
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

# Contributors

The `accepted_media_types` and `rejected_media_types` extensions were written
by Rohan Mahy.

The `message_streams` extension was written by Josh Brown.