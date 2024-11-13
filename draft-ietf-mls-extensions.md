---
title: The Messaging Layer Security (MLS) Extensions
abbrev: MLS
docname: draft-ietf-mls-extensions-latest
submissiontype: IETF
category: std

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

contributor:
 - name: Joel Alwen
   org:  Amazon
   email:  alwenjo@amazon.com
 - name: Konrad Kohbrok
   org:  Phoenix R&D
   email:  konrad.kohbrok@datashrine.de
 - name: Rohan Mahy
   org:  Rohan Mahy Consulting Services
   email:  rohan.ietf@gmail.com
 - name: Marta Mularczyk
   org:  Amazon
   email:  mulmarta@amazon.com

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

In general, while extensions can modify the protocol flow of MLS and the
associated properties in arbitrary ways, the base MLS protocol already enables a
number of functionalities that extensions can use without modifying MLS itself.
Extension authors should consider using these built-in mechanisms before
employing more intrusive changes to the protocol.

## Change Log

RFC EDITOR PLEASE DELETE THIS SECTION.

draft-05

- Include definition of ExtensionState extension
- Add safe use of AAD to Safe Extensions framework
- Clarify how capabilities negotiation works in Safe Extensions framework

draft-04

 - No changes (prevent expiration)

draft-03

- Add Last Resort KeyPackage extension
- Add Safe Extensions framework
- Add SelfRemove Proposal

draft-02

- No changes (prevent expiration)

draft-01

- Add Content Advertisement extensions

draft-00

- Initial adoption of draft-robert-mls-protocol-00 as a WG item.
- Add Targeted Messages extension (\*)

# Safe Extensions

The MLS specification is extensible in a variety of ways (see Section 13 of
{{!RFC9420}}) and describes the negotiation and other handling of extensions and
their data within the protocol. However, it does not provide guidance on how
extensions can or should safely interact with the base MLS protocol. The goal of
this section is to simplify the task of developing MLS extensions.

More concretely, this section defines the Safe Extension API, a library of
extension components which simplifies development and security analysis of
extensions, provides general guidance on using the built-in functionality of the
base MLS protocol to build extensions, defines specific examples of extensions
built on top of the Safe Extension API alongside the built-in mechanisms of the
base MLS protocol, defines a number of labels registered in IANA which can be
safely used by extensions, so that the only value an extension developer must
add to the IANA registry itself is a unique ExtensionType.

## Safe Extension API

The Safe Extension API is a library that defines a number of components from
which extensions can be built. In particular, these components provide
extensions the ability to:

- Make use of selected private and public key material from the MLS
  specification, e.g. to encrypt, decrypt, sign, verify and derive fresh key
  material.
- Inject key material via PSKs in a safe way to facilitate state agreement
  without the use of a group context extension.
- Export secrets from MLS in a way that, in contrast to the built-in export
  functionality of MLS, preserves forward secrecy of the exported secrets within
  an epoch.
- Define new WireFormat, Proposal, Credential, GroupContext, GroupInfo,
KeyPackage, and LeafNode extensions which can interact safely with arbitrary
sets of other current or future Safe Extensions.
- Anchor extension-specific state in an MLS group to ensure agreement and manage
  state acces authorization across extensions.

The Safe Extension API is not an extension itself, it only defines components
from which other extensions can be built. Some of these components modify the
MLS protocol and, therefore, so do the extensions built from them.

Where possible, the API makes use of mechanisms defined in the MLS
specification. For example, part of the safe API is the use of the
`SignWithLabel` function described in Section 5.1.2 of {{!RFC9420}}.

An extension is called safe if it does not modify the base MLS protocol or other
MLS extensions beyond using components of the Safe Extension API. The Safe
Extension API provides the following security guarantee: If an application uses
MLS and only safe MLS extensions, then the security guarantees of the base MLS
protocol and the security guarantees of safe extensions, each analyzed in
isolation, still hold for the composed extended MLS protocol. In other words,
the Safe Extension API protects applications from careless extension
developers. As long as all used extensions are safe, it is not possible that a
combination of extensions  (the developers of which did not know about each
other) impedes the security of the base MLS protocol or any used extension. No
further analysis of the combination is necessary. This also means that any
security vulnerabilities introduced by one extension do not spread to other
extensions or the base MLS.

### Core Struct Extensions

Every type of MLS extension can have data associated with it. The "MLS
Extensions Types" registry historically represented extensibility of four
core structs (`GroupContext`, `GroupInfo`, `KeyPackage`, and `LeafNode`)
that have far reaching effects on the use of the protocol. The majority of
MLS extensions registered at the time of this writing extend one or more
of these core structs.

- GroupContext Extensions: Any data in a group context extension is agreed-upon
  by all members of the group in the same way as the rest of the group state. As
  part of the GroupContext, it is also sent encrypted to new joiners via Welcome
  messages and (depending on the architecture of the application) may be
  available to external joiners. Note that in some scenarios, the GroupContext
  may also be visible to components  that implement the delivery service. While
  MLS extensions can define arbitrary GroupContext extensions, it is recommended
  to make use of `ExtensionState` extensions to store state in the group's
  GroupContext.
- GroupInfo Extensions: GroupInfo extensions are included in the GroupInfo
  struct and thus sent encrypted and authenticated by the signer of the
  GroupInfo to new joiners as part of Welcome messages. It can thus be used as a
  confidential and authenticated channel from the inviting group member to new
  joiners. Just like GroupContext extensions, they may also be visible to
  external joiners or even parts of the delivery service. Unlike GroupContext
  extensions, the GroupInfo struct is not part of the group state that all group
  members agree on.
- KeyPackage Extensions: KeyPackages (and the extensions they include) are
  pre-published by individual clients for asynchronous group joining. They are
  included in Add proposals and become part of the group state once the Add
  proposal is committed. They are, however, removed from the group state when
  the owner of the KeyPackage does the first commit with a path. As such,
  KeyPackage extensions can be used to communicate data to anyone who wants to
  invite the owner to a group, as well as the other members of the group the
  owner is added to. Note that KeyPackage extensions are visible to the server
  that provides the KeyPackages for download, as well as any part of the
  delivery service that can see the public group state.
- LeafNode Extensions: LeafNodes are a part of every KeyPackage and thus follow
  the same lifecycle. However, they are also part of any commit that includes an
  UpdatePath and clients generally have a leaf node in each group they are a member
  of. Leaf node extensions can thus be used to include member-specific data in a
  group state that can be updated by the owner at any time.

### Common Data Structures

The Safe Extension API reuses the `ExtensionType` and the "MLS Extension
Types" IANA registry used for these core structs (see Section 17.3 of
{{!RFC9420}}), even for safe extensions with no core struct changes.
This is because many extensions modify a core struct, either primarily or
to store state (related to the group or a client) associated with another
aspect of that extension.

Most Safe Extension API components also use the following data structure, which
provides domain separation by `extension_type` of various `extension_data`.

~~~ tls
struct {
  ExtensionType extension_type;
  opaque extension_data<V>;
} ExtensionContent;
~~~

Where `extension_type` is set to the type of the extension to which the
`extension_data` belongs.

When a label is required for an extension, the following data structure is
used.

~~~ tls
struct {
  opaque label;
  ExtensionContent extension_content;
} LabeledExtensionContent;
~~~

### Negotiating Support for Safe Extensions

MLS defines a `Capabilities` struct for LeafNodes (in turn used in
KeyPackages), which describes which extensions are supported by the
associated node.
However, that struct (defined in Section 7.2 of {{!RFC9420}}) only has
fields for a subset of the extensions possible in MLS, as reproduced below.

~~~ tls
...
struct {
    ProtocolVersion versions<V>;
    CipherSuite cipher_suites<V>;
    ExtensionType extensions<V>;
    ProposalType proposals<V>;
    CredentialType credentials<V>;
} Capabilities;
...
~~~

Therefore, all safe extensions MUST be represented by their `extension_type`
in the `extensions` vector (originally intended for core struct extensions),
regardless of their type.

If the LeafNode supports any safe extension Credentials, the `credentials`
vector will contain any non-safe credentials supported, plus the `extension_credential` defined in {extension-credential}.

If the LeafNode supports any safe extension Proposals, then `proposals` will
contain any non-default non-safe extensions, and whichever safe extension
proposal types defined in {mls-proposal-types} are relevant to the supported
safe proposals.

Likewise, the `required_capabilities` GroupContext extension (defined
in Section 11.1 of {{!RFC9420}} and reproduced below) contains all
mandatory to support non-default non-safe, and safe extensions in its
`extension_types` vector. Its `credential_types` vector contains any
mandatory non-safe credential types, plus `extensions_credential` if any
safe credential is required. Its `proposal_types` vector contains any
mandatory to support non-default non-safe Proposals, and the relevant safe
proposal type or types corresponding to any required safe proposals.

~~~
struct {
    ExtensionType extension_types<V>;
    ProposalType proposal_types<V>;
    CredentialType credential_types<V>;
} RequiredCapabilities;
~~~


### Hybrid Public Key Encryption (HPKE) {#safe-hpke}

This component of the Safe Extension API allows extensions to make use of all
HPKE key pairs generated by MLS. An extension identified by an ExtensionType can
use any HPKE key pair for any operation defined in {{!RFC9180}}, such as
encryption, exporting keys and the PSK mode, as long as the `info` input to
`Setup<MODE>S` and `Setup<MODE>R` is set to LabeledExtensionContent with
`extension_type` set to ExtensionType. The `extension_data` can be set to an
arbitrary Context specified by the extension designer (and can be empty if not
needed). For example, an extension can use a key pair PublicKey, PrivateKey to
encrypt data as follows:

~~~ tls
SafeEncryptWithContext(ExtensionType, PublicKey, Context, Plaintext) =
    SealBase(PublicKey, LabeledExtensionContent, "", Plaintext)

SafeDecryptWithContext(ExtensionType, PrivateKey, Context, KEMOutput, Ciphertext) =
    OpenBase(KEMOutput, PrivateKey, LabeledExtensionContent, "", Ciphertext)
~~~

Where the fields of LabeledExtensionContent are set to

~~~ tls
label = "MLS 1.0 ExtensionData"
extension_type = ExtensionType
extension_data = Context
~~~

For operations involving the secret key, ExtensionType MUST be set to the
ExtensionType of the implemented extension, and not to the type of any other
extension. In particular, this means that an extension cannot decrypt data meant
for another extension, while extensions can encrypt data to other extensions.

In general, a ciphertext encrypted with a PublicKey can be decrypted by any
entity who has the corresponding PrivateKey at a given point in time according
to the MLS protocol (or extension). For convenience, the following list
summarizes lifetimes of MLS key pairs.

- The key pair of a non-blank ratchet tree node. The PrivateKey of such a key pair
  is known to all members in the node’s subtree. In particular, a PrivateKey of a
  leaf node is known only to the member in that leaf. A member in the subtree
  stores the PrivateKey for a number of epochs, as long as the PublicKey does not
  change. The key pair of the root node SHOULD NOT be used, since the external key
  pair recalled below gives better security.
- The external_priv, external_pub key pair used for external initialization. The
  external_priv key is known to all group members in the current epoch. A member
  stores external_priv only for the current epoch. Using this key pair gives
  better security guarantees than using the key pair of the root of the ratchet
  tree and should always be preferred.
- The init_key in a KeyPackage and the corresponding secret key. The secret key
  is known only to the owner of the KeyPackage and is deleted immediately after it
  is used to join a group.

### Signature Keys

MLS session states contain a number of signature keys including the ones in the
LeafNode structs. Extensions can safely sign content and verify signatures using
these keys via the SafeSignWithLabel and SafeVerifyWithLabel functions,
respectively, much like how the basic MLS protocol uses SignWithLabel and
VerifyWithLabel.

In more detail, an extension identified by ExtensionType should sign and verify using:

~~~ tls
SafeSignWithLabel(ExtensionType, SignatureKey, Label, Content) =
    SignWithLabel(SignatureKey, "LabeledExtensionContent", LabeledExtensionContent)

SafeVerifyWithLabel(ExtensionType, VerificationKey, Label, Content, SignatureValue) =
    VerifyWithLabel(VerificationKey, "LabeledExtensionContent", LabeledExtensionContent, SignatureValue)
~~~

Where the fields of LabeledExtensionContent are set to

~~~ tls
label = Label
extension_type = ExtensionType
extension_data = Content
~~~

For signing operations, the ExtensionType MUST be set to the ExtensionType of
the implemented extension, and not to the type of any other extension. In
particular, this means that an extension cannot produce signatures in place of
other extensions. However, extensions can verify signatures computed by other
extensions. Note that domain separation is ensured by explicitly including the
ExtensionType with every operation.

### Exporting Secrets

An extension can use MLS as a group key agreement protocol by exporting symmetric keys.
Such keys can be exported (i.e. derived from MLS key material) in two phases per
epoch: Either at the start of the epoch, or during the epoch. Derivation at the
start of the epoch has the added advantage that the source key material is
deleted after use, allowing the derived key material to be deleted later even
during the same MLS epoch to achieve forward secrecy. The following protocol
secrets can be used to derive key from for use by extensions:

- epoch_secret at the beginning of an epoch
- extension_secret during an epoch

The extension_secret is an additional secret derived from the epoch_secret at
the beginning of the epoch in the same way as the other secrets listed in Table
4 of {{!RFC9420}} using the label "extension".

Any derivation performed by an extension either from the epoch_secret or the
extension_secret has to use the following function:

~~~ tls
DeriveExtensionSecret(Secret, Label) =
  ExpandWithLabel(Secret, "ExtensionExport " + ExtensionType + " " + Label)
~~~

Where ExpandWithLabel is defined in Section 8 of {{!RFC9420}} and where ExtensionType
MUST be set to the ExtensionType of the implemented extension.

### Pre-Shared Keys (PSKs)

PSKs represent key material that is injected into the MLS key schedule when
creating or processing a commit as defined in Section 8.4 of {{!RFC9420}}. Its
injection into the key schedule means that all group members have to agree on
the value of the PSK.

While PSKs are typically cryptographic keys which due to their properties add to
the overall security of the group, the PSK mechanism can also be used to ensure
that all members of a group agree on arbitrary pieces of data represented as
octet strings (without the necessity of sending the data itself over the wire).
For example, an extension can use the PSK mechanism to enforce that all group
members have access to and agree on a password or a shared file.

This is achieved by creating a new epoch via a PSK proposal. Transitioning to
the new epoch requires using the information agreed upon.

To facilitate using PSKs in a safe way, this document defines a new PSKType for
extensions. This provides domain separation between pre-shared keys used by the
core MLS protocol and applications, and between those used by different extensions.

~~~tls
enum {
  reserved(0),
  external(1),
  resumption(2),
  extensions(3),
  (255)
} PSKType;

struct {
  PSKType psktype;
  select (PreSharedKeyID.psktype) {
    case external:
      opaque psk_id<V>;

    case resumption:
      ResumptionPSKUsage usage;
      opaque psk_group_id<V>;
      uint64 psk_epoch;

    case extensions:
      ExtensionType extension_type;
      opaque psk_id<V>;
  };
  opaque psk_nonce<V>;
} PreSharedKeyID;
~~~

### Extension state: anchoring, storage and agreement

The safe extension framework can help an MLS extension ensure that all group
members agree on a piece of extension-specific state by using the
`ExtensionState` GroupContext extension. The ownership of an `ExtensionState`
extension in the context of the safe extension framework is determined by the
`extension_type` field. The extension with a matching `extension_type` is called
the owning extension.

~~~tls
enum {
  reserved(0),
  read(1),
  none(2),
 (255)
} Permissions;

enum {
  reserved(0),
  hash(1),
  data(2),
} HashOrData;

struct {
  HashOrData hash_or_data;
  select(hash_or_data) {
    case hash:
      HashReference state_hash;
    case data:
      opaque state<V>;
  }
} ExtensionPayload;

struct {
  extensionType extension_type;
  Permissions read;
  ExtensionPayload payload;
} ExtensionState;
~~~

The `ExtensionState` GroupContext extension contains data either directly (if
`hash_or_data = data`) or inditectly via a hash (if `hash_or_data = hash`).

The owning extension can read and write the state stored in an `ExtensionState`
extension using an extension-defined proposal, or with the existing
GroupContextExtensions proposal.

The `read` variable determines the permissions that other MLS extensions have
w.r.t. the data stored within. `read` allows other MLS extensions to read that
data via their own proposals, while `none` marks the data as private to the
owning MLS extension.

Other extensions may never write to the `ExtensionState` of the owning MLS
extension.

#### Direct vs. hash-based storage

Storing the data directly in the `ExtensionState` means the data becomes part of
the group state. Depending on the application design, this can be advantageous,
because it is distributed via Welcome messages. However, it could also mean that
the data is visible to the delivery service. Additionally, if the application
makes use of GroupContextExtension proposals, it may be necessary to send all of
the data with each such extension.

Including the data by hash only allows group members to agree on the data
indirectly, relying on the collision resistance of the associated hash function.
The data itself, however, may have to be transmitted out-of-band to new joiners.

#### GroupContextExtensions

MLS allows applications to modify GroupContext extensions via the
GroupContextExtension proposal. However, control via that proposal involves
including all GroupContext extensions in each such proposal. This makes data
management more costly than via extension-specific proposals, which can, for
example, include only the data to be changed for a given GroupContext extension,
or define semantics that allow modification based on local data only.

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

- The application might have the committer include an AppAck proposal whenever a
  Commit is sent, so that other members could know when one of their messages
  did not reach the committer.

- The application could have a client send an AppAck whenever an application
  message is sent, covering all messages received since its last AppAck.  This
  would provide a complete view of any losses experienced by active members.

- The application could simply have clients send AppAck proposals on a timer, so
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

Targeted Messages makes use the Safe Extension API as defined in {{safe-extension-api}}.
reuse mechanisms from {{mls-protocol}}, in particular {{hpke}}.

### Format

This extension defines a new WireFormat `TargetedMessage`.

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

Targeted messages uses HPKE to encrypt the message content between two leaves.

#### Sender data encryption

In addition, `TargetedMessageSenderAuthData` is encrypted in a similar way to
`MLSSenderData` as described in section 6.3.2 in {{mls-protocol}}. The
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

~~~ tls
sender_auth_data_secret
  = DeriveExtensionSecret(extension_secret, "targeted message sender auth data")

ciphertext_sample = hpke_ciphertext[0..KDF.Nh-1]

sender_data_key = ExpandWithLabel(sender_auth_data_secret, "key",
                      ciphertext_sample, AEAD.Nk)
sender_data_nonce = ExpandWithLabel(sender_auth_data_secret, "nonce",
                      ciphertext_sample, AEAD.Nn)
~~~

The Additional Authenticated Data (AAD) for the `SenderAuthData` ciphertext is
the first three fields of `TargetedMessage`:

~~~ tls
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

~~~ tls
targeted_message_psk
  = DeriveExtensionSecret(extension_secret, "targeted message psk")
~~~

The functions `SealAuth` and `OpenAuth` defined in {{hpke}} are used as
described in {{safe-hpke}} with an empty context. Other functions are defined in
{{mls-protocol}}.

#### Authentication with HPKE

The sender MUST set the authentication scheme to
`TargetedMessageAuthScheme.HPKEAuthPsk`.

As described in {{safe-hpke}} the `hpke_context` is a LabeledExtensionContent struct
with the following content, where `group_context` is the serialized context of
the group.

~~~ tls
label = "MLS 1.0 ExtensionData"
extension_type = ExtensionType
extension_data = group_context
~~~


The sender then computes the following:

~~~ tls
(kem_output, hpke_ciphertext) = SealAuthPSK(receiver_node_public_key,
                                            hpke_context,
                                            targeted_message_tbm,
                                            message,
                                            targeted_message_psk,
                                            psk_id,
                                            sender_node_private_key)
~~~

The recipient computes the following:

~~~ tls
message = OpenAuthPSK(kem_output,
                      receiver_node_private_key,
                      hpke_context,
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

The sender then computes the following with `hpke_context` defined as in
{{authentication-with-hpke}}:

~~~ tls
(kem_output, hpke_ciphertext) = SealPSK(receiver_node_public_key,
                                        hpke_context,
                                        targeted_message_tbm,
                                        message,
                                        targeted_message_psk,
                                        epoch)
~~~

The signature is computed as follows, where the `extension_type` is the type of
this extension (see {{iana-considerations}}).

~~~ tls
signature = SafeSignWithLabel(extension_type, ., "TargetedMessageTBS", targeted_message_tbs)
~~~

The recipient computes the following:

~~~ tls
message = OpenPSK(kem_output,
                  receiver_node_private_key,
                  hpke_context,
                  targeted_message_tbm,
                  hpke_ciphertext,
                  targeted_message_psk,
                  epoch)
~~~

The recipient MUST verify the message authentication:

~~~ tls
SafeVerifyWithLabel.verify(extension_type,
                        sender_leaf_node.signature_key,
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
an MLS group from removing itself immediately from the group. (To cause
an immediate change in the group, a member must send a Commit message.
However the sender of a Commit message knows the keying material of the
new epoch and therefore needs to be part of the group.) Instead a member
wishing to remove itself can send a Remove Proposal and wait for another
member to Commit its Proposal.

Unfortunately, MLS clients that join via an External Commit ignore
pending, but otherwise valid, Remove Proposals. The member trying to remove
itself has to monitor the group and send a new Remove Proposal in every new
epoch until the member is removed. In a
group with a burst of external joiners, a member connected over a
high-latency link (or one that is merely unlucky) might have to wait
several epochs to remove itself. A real-world situation in which this happens
is a member trying to remove itself from a conference call as several dozen
new participants are trying to join (often on the hour).

This section describes a new `SelfRemove` Proposal extension type. It is
designed to be included in External Commits.

### Extension Description

This document specifies a new MLS Proposal type called `SelfRemove`. Its syntax
is described using the TLS Presentation Language [@!RFC8446] below (its content
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

An MLS client which supports this extension can send a
SelfRemove Proposal whenever it would like to remove itself
from a self-remove-capable group. Because the point of a
SelfRemove Proposal is to be available to external joiners
(which are not yet members), these proposals MUST be sent
in an MLS PublicMessage.

Whenever a member receives a SelfRemove Proposal, it includes
it along with any other pending Propsals when sending a Commit.
It already MUST send a Commit of pending Proposals before sending
new application messages.

When a member receives a Commit referencing one or more SelfRemove Proposals,
it treats the proposal like a Remove Proposal, except the leaf node to remove
is determined by looking in the Sender `leaf_index` of the original Proposal.
The member is able to verify that the Sender was a member.

Whenever a new joiner is about to join a self-remove-capable group with an
External Commit, the new joiner MUST fetch any pending SelfRemove Proposals
along with the GroupInfo object, and include the SelfRemove Proposals
in its External Commit by reference. (An ExternalCommit can contain zero or
more SelfRemove proposals). The new joiner MUST validate the SelfRemove
Proposal before including it by reference, except that it skips the validation
of the `membership_tag` because a non-member cannot verify membership.

During validation, SelfRemove proposals are processed after Update proposals
and before Remove proposals. If there is a pending SelfRemove proposal for a specific
leaf node and a pending Remove proposal for the same leaf node, the Remove proposal is
invalid. A client MUST NOT issue more than one SelfRemove proposal per epoch.

The MLS Delivery Service (DS) needs to validate SelfRemove Proposals it
receives (except that it cannot validate the `membership_tag`). If the DS
provides a GroupInfo object to an external joiner, the DS SHOULD attach any
SelfRemove proposals known to the DS to the GroupInfo object.

As with Remove proposals, clients need to be able to receive a Commit
message which removes them from the group via a SelfRemove. If the DS does
not forward a Commit to a removed client, it needs to inform the removed
client out-of-band.

## Last resort KeyPackages

Type: KeyPackage extension

### Description

Section 10 of {{!RFC9420}} details that clients are required to pre-publish
KeyPackages s.t. other clients can add them to groups asynchronously. It also
states that they should not be re-used:

> KeyPackages are intended to be used only once and SHOULD NOT be reused except
> in the case of a "last resort" KeyPackage (see Section 16.8). Clients MAY
> generate and publish multiple KeyPackages to support multiple cipher suites.

Section 16.8 of {{!RFC9420}} then introduces the notion of last-resort
KeyPackages as follows:

> An application MAY allow for reuse of a "last resort" KeyPackage in order to
> prevent denial-of-service attacks.

However, {{!RFC9420}} does not specify how to distinguish regular KeyPackages
from last-resort ones. The last_resort_key_package KeyPackage extension defined
in this section fills this gap and allows clients to specifically mark
KeyPackages as KeyPackages of last resort that MAY be used more than once in
scenarios where all other KeyPackages have already been used.

The extension allows clients that pre-publish KeyPackages to signal to the
Delivery Service which KeyPackage(s) are meant to be used as last resort
KeyPackages.

An additional benefit of using an extension rather than communicating the
information out-of-band is that the extension is still present in Add proposals.
Clients processing such Add proposals can authenticate that a KeyPackage is a
last-resort KeyPackage and MAY make policy decisions based on that information.

### Format

The purpose of the extension is simply to mark a given KeyPackage, which means
it carries no additional data.

As a result, a LastResort Extension contains the ExtensionType with an empty
`extension_data` field.

# IANA Considerations

This document requests the addition of various new values under the heading
of "Messaging Layer Security".  Each registration is organized under the
relevant registry Type.

RFC EDITOR: Please replace XXXX throughout with the RFC number assigned to
this document

## MLS Wire Formats

### MLS Extension Message

 * Value: 0x0006
 * Name: mls_extension_message
 * Recommended: Y
 * Reference: RFC XXXX

## MLS Extension Types

This document updates the MLS Extension Types registry to insert a new
column ("Safe") between the "Recommended" column and the "Reference"
column. The value of the "Safe" column for the first (0x0000) and last
(0xF000-0xFFFF) rows is "-" while the value of all other existing rows is
"N".

- Safe: Whether the extension is a Safe Extension as defined in Section 2 of
 RFC XXXX.  Valid values are:
    - "Y", indicating the extension is a Safe Extension;
    - "N", indicating the extension is not a Safe Extension; or
    - "-", indicating a reserved value which is not a single extension.

This document also extends the list of allowable values for the "Message(s)"
column, such that the list may be empty (represented by "-") if the
extension is a Safe Extension.

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

### last_resort_key_package MLS Extension

The last_resort_key_package MLS Extension Type is used inside KeyPackage
objects. It marks the KeyPackage for usage in last resort scenarios and contains
no additional data.

* Value: 0x000A
* Name: last_resort_key_package
* Message(s): KP: This extension may appear in KeyPackage objects
* Recommended: Y
* Reference: RFC XXXX

## MLS Proposal Types

### AppAck Proposal

* Value: 0x000b
* Name: app_ack
* Recommended: Y
* Path Required: Y
* Reference: RFC XXXX

### SelfRemove Proposal

The `self_remove` MLS Proposal Type is used for a member to remove itself
from a group more efficiently than using a `remove` proposal type, as the
`self_remove` type is permitted in External Commits.

* Value: 0x000c
* Name: self_remove
* Recommended: Y
* External: N
* Path Required: Y

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
