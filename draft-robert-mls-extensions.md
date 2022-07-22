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

informative:
  mls-protocol:
    target: https://datatracker.ietf.org/doc/draft-ietf-mls-protocol/](https://datatracker.ietf.org/doc/draft-ietf-mls-protocol/
    title: The Messaging Layer Security (MLS) Protocol
  
  hpke-security-considerations:
    target: https://www.rfc-editor.org/rfc/rfc9180.html#name-key-compromise-impersonatio](https://www.rfc-editor.org/rfc/rfc9180.html#name-key-compromise-impersonatio
    title: HPKE Security Considerations

--- abstract

This document describes extensions to the Messaging Layer Security (MLS) protocol.

--- middle

# Introduction

This document describes extensions to {{mls-protocol}} that are not part of the main protocol specification. The protocol
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

## Targeted messages

### Description

MLS application messages make sending encrypted messages to all group members easy and efficient. Sometimes application protocols mandate that messages are only sent to specific group members, either for privacy or for efficiency reasons.

Targeted messages are a way to achieve this without having to create a new group with the sender and the specific recipients – which might not be possible or desired. Instead, targeted messages define the format and encryption of a message that is sent from a member of an existing group to another member of that group.

The goal is to provide a one-shot messaging mechanism that provides confidentiality and authentication.

### Format

This extensions extens the MLS protocol to include a new message type, `TargetedMessage` in `WireFormat` and `MLSMessage`:

```
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
```

The `TargetedMessage` message type is defined as follows:

```
struct {
	opaque group_id<V>;
	uint64 epoch;
	uint32 recipient_leaf_index;
	opaque authenticated_data<V>;
	opaque encrypted_sender_data<V>;
	opaque encrypted_targeted_message_content<V>;
} TargetedMessage;

enum {
	HPKEAuth,
	Signature,
} TargetedMessageAuthScheme;

struct {
	TargetedMessageAuthScheme authentication_scheme;
	select (authentication_scheme) {
		case HPKEAuth:
			opaque mac<V>;
		case Signature:
			opaque signature<V>;
	}
	HPKECiphertext ciphertext;
} TargetedMessageContent;

struct {
	opaque group_id<V>;
	uint64 epoch;
	uint32 recipient_leaf_index;
	opaque authenticated_data<V>;
	opaque encrypted_sender_data<V>;
	TargetedMessageAuthScheme authentication_scheme;
} TargetedMessageTBM;

struct {
	TargetedMessageTBM targeted_message_tbm;
	HPKECiphertext hpke_ciphertext;
} TargetedMessageTBS;

struct {
	opaque group_id<V>;
	uint64 epoch;
	opaque label<V> = "MLS 1.0 targeted message psk";
} PSKId;
```

### Encryption

Targeted messages use HPKE to encrypt the message content between two leaves. The HPKE keys of the `LeafNode` are used to that effect, namely the `encryption_key` field.

In addition, the sender data encryption from section 7.3.2 {{mls-protocol}} is used to encrypt `MLSSenderData`. `MLSSenderData.leaf_index` is the leaf index of the sender. The `MLSSenderData.generation` field is not used and MUST be set to 0.

### Authentication

For ciphersuites that support it, HPKE `mode_auth_psk` is used for authentication. For other ciphersuites, HPKE `mode_psk` is used along with a signature. The authentication scheme is indicated by the `authentication_scheme` field in `TargetedMessageContent`. See {{guidance-on-authentication-schemes}} for more information.

For the PSK part of the authentication, clients export a dedicated secret:

```
targeted_message_psk = MLS-Exporter("targeted message psk", "", KDF.Nh)
```

#### Authentication with HPKE

The sender MUST set the authentication scheme to `TargetedMessageAuthScheme.HPKEAuth`. 

The sender then computes the following:

```
hpke_ciphertext = SealAuthPSK(receiver_node_public_key, group_context, targeted_message_tbm, message, targeted_message_psk, psk_id, sender_node_private_key)
```

The recipient computes the following:

```
message = OpenAuthPSK(hpke_ciphertext.enc, receiver_node_private_key, group_context, targeted_message_tbm, hpke_ciphertext.ct, targeted_message_psk, psk_id, sender_node_public_key)
```

#### Authentication with signatures

The sender MUST set the authentication scheme to `TargetedMessageAuthScheme.Signature`. 

The sender then computes the following:

```
hpke_ciphertext = SealPSK(receiver_node_public_key, group_context, targeted_message_tbm, message, targeted_message_psk, epoch)

signature = SignWithLabel(., "targeted message", targeted_message_tbs)
```

The recipient computes the following:

```
message = OpenPSK(hpke_ciphertext.enc, receiver_node_private_key, group_context, targeted_message_tbm, hpke_ciphertext.ct, targeted_message_psk, epoch)
```

The recipient MUST verify the message authentication:

```
VerifyWithLabel.verify(sender_leaf_node.signature_key, "targeted message", targeted_message_tbs, signature)
```

### Guidance on authentication schemes

If the group’s ciphersuite does not support HPKE `mode_auth_psk`, implementations MUST choose `TargetedMessageAuthScheme.Signature`.

If the group’s ciphersuite does support HPKE `mode_auth_psk`, implementations CAN choose `TargetedMessageAuthScheme.HPKEAuth` if better efficiency and/or repudiability is desired. Implementations SHOULD consult {{hpke-security-considerations}} beforehand.

# IANA Considerations

This document requests the creation of the following new IANA registries:

* MLS Extension Types ({{extended-mls-extension-types}})
* MLS Proposal Types ({{extended-mls-proposal-types}})

All of these registries should be under a heading of "Messaging Layer Security",
and assignments are made via the Specification Required policy {{!RFC8126}}.

RFC EDITOR: Please replace XXXX throughout with the RFC number assigned to
this document

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
