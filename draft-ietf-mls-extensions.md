---
title: The Messaging Layer Security (MLS) Extensions
abbrev: MLS
docname: draft-ietf-mls-extensions-latest
submissiontype: IETF
category: std

number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "Messaging Layer Security"
keyword:
 - messaging layer security
 - end-to-end encryption
 - application api
 - extension
 - extensibility
venue:
  group: "Messaging Layer Security"
  type: "Working Group"
  mail: "mls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mls/"
  github: "mlswg/mls-extensions"
  latest: "https://mlswg.github.io/mls-extensions/draft-ietf-mls-extensions.html"

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
 - name: Richard Barnes
   org: Cisco Systems
   email: rlb@ipv.sx

normative:

informative:

--- abstract

The Messaging Layer Security (MLS) protocol is an asynchronous group
authenticated key exchange protocol.  MLS provides a number of capabilities
to applications, as well as several extension points internal to the protocol.  This
document provides a consolidated application API, guidance for how the
protocol's extension points should be used, and a few concrete examples of both
core protocol extensions and uses of the application API.

--- middle

# Introduction

This document defines extensions to MLS {{!RFC9420}} that are not part of the
main protocol specification, and uses them to explain how to extend the
core operation of the MLS protocol. It also describes how applications can
safely interact with the MLS to take advantage of security features of MLS.

The MLS protocol is designed to be integrated into applications, in order to
provide security services that the application requires.  There are two
questions to answer when designing such an integration:

1. How does the application provide the services that MLS requires?
2. How does the application use MLS to get security benefits?

The MLS Architecture {{?I-D.ietf-mls-architecture}} describes the requirements
for the first of these questions, namely the structure of the Delivery Service
and Authentication Service that MLS requires. The next section of this document
focuses on the second question.

MLS itself offers some basic functions that applications can use, such as the
secure message encapsulation (PrivateMessage), the MLS exporter, and the epoch
authenticator.  Current MLS applications make use of these mechanisms to acheive
a variety of confidentiality and authentication properties.

As application designers become familiar with MLS, there is
interest in leveraging other cryptographic tools that an MLS group provides:

- HPKE (Hybrid Public Key Encryption {{!RFC9180}}) and signature key pairs for
  each member, where the private key is known only to that member, and the
  public key is authenticated to the other members.

- A pre-shared key mechanism that can allow an application to inject data into
  the MLS key schedule.

- An exporter mechanism that allows applications to derive secrets from the MLS
  key schedule.

- Association of data with Commits as a synchronization mechanism.

- Binding of information to the GroupContext to confirm group agreement.

There is also interest in exposing an MLS group to multiple loosely-coordinated
components of an application.  To accommodate such cases, the above mechanisms
need to be exposed in such a way that the usage of different components do not
conflict with each other, or with MLS itself.

This document defines a set of mechanisms that application components can use to
ensure that their use of these facilities is properly domain-separated from MLS
itself, and from other application components that might be using the same MLS
group.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document makes heavy use of the terminology and the names of structs in the
MLS specification {{!RFC9420}}.  In addition, we introduce the following new terms:

Application:
: The system that instantiates, manages, and uses an MLS group.  Each MLS group
is used by exactly one application, but an application may maintain multiple
groups.

Application component:
: A subsystem of an application that has access to an MLS group.

Component ID:
: An identifier for an application component.  These identifiers are assigned by
the application.

# Developing Extensions for the MLS Protocol

MLS is highly extensible, and was designed to be used in a variety of different
applications. As such, it is important to separate extensions that change the
behavior of an MLS stack, and application usages of MLS that just take advantage
of features of MLS or specific extensions (hereafter referred to as *components*). Furthermore it is essential that application components do not change the security properties of MLS or require new security analysis of the MLS protocol itself.

# The Safe Application Interface

The mechansms in this section take MLS mechanisms that are either not
inherently designed to be used by applications, or not inherently designed to be
used by multiple application components, and adds a domain separator that
separates application usage from MLS usage, and application components' usage
from each other:

- Public-key encryption operations are tagged so that encrypted data
  will only decrypt in the context of a given component.

- Signing operations are similarly tagged so that signatures will only verify
  in the context of a given component.

- Exported values include an identifier for the component to which they are
  being exported, so that different components will get different exported
  values.

- Pre-shared keys are identified as originating from a specific component, so
  that differnet components' contributions to the MLS key schedule will not
  collide.

- Additional Authenticated Data (AAD) can be domain separated by component.

Similarly, the content of application messages (`application_data`) can be
distinguished and routed to different parts of an application according to
the media type of that content using the content negotiation mechanism defined
in {{content-advertisement}}.

We also define new general mechanisms that allow applications to take advantage
of the extensibility mechanisms of MLS without having to define extensions
themselves:

- An `app_data_dictionary` extension type that associates application data with
  MLS messages, or with the state of the group.

- An AppEphemeral proposal type that enables arbitrary application data to
  be associated to a Commit.

- An AppDataUpdate proposal type that enables efficient updates to
  an `app_data_dictionary` GroupContext extension.

As with the above, information carried in these proposals and extension marked
as belonging to a specific application component, so that components can manage
their information independently.

The separation between components is acheived by the application assigning each
component a unique component ID number.  These numbers are then incorporated
into the appopriate calculations in the protocol to achieve the required
separation.

## Component IDs

A component ID is a four-byte value that uniquely identifies a component within
the scope of an application.

~~~
uint32 ComponentID;
~~~

> TODO: What are the uniqueness requirements on these?  It seems like the more
> diversity, the better.  For example, if a ComponentID is reused across
> applications (e.g., via an IANA registry), then there will be a risk of replay
> across applications.  Maybe we should include a binder to the group/epoch as
> well, something derived from the key schedule.

> TODO: It might be better to frame these in terms of "data types" instead of
> components, to avoid presuming software architecture.  Though that makes less
> sense for the more "active" portions of the API, e.g., signing and encryption.

When a label is required for an operation, the following data structure is used.
The `label` field identifies the operation being performed.  The `component_id`
field identifies the component performing the operation.  The `context` field is
specified by the operation in question.

~~~ tls
struct {
  opaque label<V>;
  ComponentID component_id;
  opaque context<V>;
} ComponentOperationLabel;
~~~


## Hybrid Public Key Encryption (HPKE) Keys {#safe-hpke}

This component of the API allows components to make use of the HPKE key pairs
generated by MLS. A component identified by a ComponentID can use any HPKE
key pair for any operation defined in {{!RFC9180}}, such as encryption,
exporting keys and the PSK mode, as long as the `info` input to `Setup<MODE>S`
and `Setup<MODE>R` is set to ComponentOperationLabel with `component_id` set
to the appopriate ComponentID. The `context` can be set to an arbitrary Context
specified by the application designer and can be empty if not needed. For
example, a component can use a key pair PublicKey, PrivateKey to encrypt data
as follows:

~~~ tls
SafeEncryptWithContext(ComponentID, PublicKey, Context, Plaintext) =
  SealBase(PublicKey, ComponentOperationLabel, "", Plaintext)

SafeDecryptWithContext(ComponentID, PrivateKey, Context,
  KEMOutput, Ciphertext) = OpenBase(KEMOutput, PrivateKey,
                             ComponentOperationLabel, "", Ciphertext)
~~~

Where the fields of ComponentOperationLabel are set to

~~~ tls
label = "MLS 1.0 Application"
component_id = ComponentID
context = Context
~~~

> TODO: Should this use EncryptWithLabel / DecryptWithLabel?  That wouldn't
> cover other modes / exports, but you could say "mutatis mutandis".

For operations involving the secret key, ComponentID MUST be set to the
ComponentID of the component performing the operation, and not to the ID of
any other component. In particular, this means that a component cannot decrypt
data meant for another component, while components can encrypt data that other
components can decrypt.

In general, a ciphertext encrypted with a PublicKey can be decrypted by any
entity who has the corresponding PrivateKey at a given point in time according
to the MLS protocol (or application component). For convenience, the following
list summarizes lifetimes of MLS key pairs.

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


## Signature Keys

MLS session states contain a number of signature keys including the ones in the
LeafNode structs. Application components can safely sign content and verify
signatures using these keys via the SafeSignWithLabel and SafeVerifyWithLabel
functions, respectively, much like how the basic MLS protocol uses SignWithLabel
and VerifyWithLabel.

In more detail, a component identified by ComponentID should sign and verify
using:

~~~ tls
SafeSignWithLabel(ComponentID, SignatureKey, Label, Content) =
   SignWithLabel(SignatureKey, "ComponentOperationLabel",
      ComponentOperationLabel)

SafeVerifyWithLabel(ComponentID, VerificationKey, Label, Content,
  SignatureValue) = VerifyWithLabel(VerificationKey,
                      "ComponentOperationLabel",
                       ComponentOperationLabel,
                       SignatureValue)
~~~

Where the fields of ComponentOperationLabel are set to

~~~ tls
label = Label
component_id = ComponentID
context = Content
~~~

For signing operations, the ComponentID MUST be set to the ComponentID of the
component performing the signature, and not to the ID of any other component.
This means that a component cannot produce signatures in place of other
component. However, components can verify signatures computed by other
components. Domain separation is ensured by explicitly including the ComponentID
with every operation.

## Exported Secrets

An application component can use MLS as a group key agreement protocol by
exporting symmetric keys.  Such keys can be exported (i.e. derived from MLS key
material) in two phases per epoch: Either at the start of the epoch, or during
the epoch. Derivation at the start of the epoch has the added advantage that the
source key material is deleted after use, allowing the derived key material to
be deleted later even during the same MLS epoch to achieve forward secrecy. The
following protocol secrets can be used to derive key from for use by application
components:

- `exporter_secret` at the beginning of an epoch
- `application_export_secret` during an epoch

The `application_export_secret` is an additional secret derived from the
`epoch_secret` at the beginning of the epoch in the same way as the other
secrets listed in Table 4 of {{!RFC9420}} using the label "application_export".

Any derivation performed by an application component either from the
`exporter_secret` or the `application_export_secret` has to use the following
function:

~~~ tls
DeriveApplicationSecret(Secret, Label) =
  ExpandWithLabel(Secret, "ApplicationExport " +
                  ComponentID + " " + Label)
~~~

Where ExpandWithLabel is defined in {{Section 8 of RFC9420}} and where
ComponentID MUST be set to the ComponentID of the component performing the
export.

> TODO: This section seems over-complicated to me.  Why is it not sufficient to
> just use the `exporter_secret`?  Or the `MLS-Exporter` mechanism with a
> label structured to include the ComponentID?


## Pre-Shared Keys (PSKs)

PSKs represent key material that is injected into the MLS key schedule when
creating or processing a commit as defined in {{Section 8.4 of !RFC9420}}. Its
injection into the key schedule means that all group members have to agree on
the value of the PSK.

While PSKs are typically cryptographic keys which due to their properties add to
the overall security of the group, the PSK mechanism can also be used to ensure
that all members of a group agree on arbitrary pieces of data represented as
octet strings (without the necessity of sending the data itself over the wire).
For example, a component can use the PSK mechanism to enforce that all group
members have access to and agree on a password or a shared file.

This is achieved by creating a new epoch via a PSK proposal. Transitioning to
the new epoch requires using the information agreed upon.

To facilitate using PSKs in a safe way, this document defines a new PSKType for
application components. This provides domain separation between pre-shared keys
used by the core MLS protocol and applications, and between those used by
different components.

~~~ tls-presentation
enum {
  // ...
  application(3),
  (255)
} PSKType;

struct {
  PSKType psktype;
  select (PreSharedKeyID.psktype) {
    // ...
    case application:
      ComponentID component_id;
      opaque psk_id<V>;
  };
  opaque psk_nonce<V>;
} PreSharedKeyID;
~~~

> TODO: It seems like you could also do this by structuring the `external`
> PSKType as (component_id, psk_id).  I guess this approach separates this API
> from other external PSKs.


## Attaching Application Data to MLS Messages

The MLS GroupContext, LeafNode, KeyPackage, and GroupInfo objects each have an
`extensions` field that can carry additional data not defined by the MLS
specification.  The `app_data_dictionary` extension provides a generic container
that applications can use to attach application data to these messages.  Each
usage of the extension serves a slightly different purpose:

* GroupContext: Confirms that all members of the group agree on the application
  data, and automatically distributes it to new joiners.

* KeyPackage and LeafNode: Associates the application data to a particular
  client, and advertises it to the other members of the group.

* GroupInfo: Distributes the application data confidentially to the new joiners
  for whom the GroupInfo is encrypted (as a Welcome message).

The content of the `app_data_dictionary` extension is a serialized
AppDataDictionary object:

~~~ tls-presentation
struct {
    ComponentID component_id;
    opaque data<V>;
} ComponentData;

struct {
    ComponentData component_data<V>;
} AppDataDictionary;
~~~

The entries in the `component_data` MUST be sorted by `component_id`, and there
MUST be at most one entry for each `component_id`.

An `app_data_dictionary` extension in a LeafNode, KeyPackage, or GroupInfo can
be set when the object is created.  An `app_data_dictionary` extension in the
GroupContext needs to be managed using the tools available to update GroupContext extensions. The creator of the group can set extensions unilaterally. Thereafter, the AppDataUpdate proposal described in the next section is used to update the `app_data_dictionary` extension.

## Updating Application Data in the GroupContext {#appdataupdate}

Updating the `app_data_dictionary` with a GroupContextExtensions proposal is
cumbersome.  The application data needs to be transmitted in its entirety,
along with any other extensions, whether or not they are being changed.  And a
GroupContextExtensions proposal always requires an UpdatePath, which updating
application state never should.

The AppDataUpdate proposal allows the `app_data_dictionary` extension to
be updated without these costs.  Instead of sending the whole value of the
extension, it sends only an update, which is interpreted by the application to
provide the new content for the `app_data_dictionary` extension.  No other
extensions are sent or updated, and no UpdatePath is required.

~~~
enum {
    invalid(0),
    update(1),
    remove(2),
    (255)
} AppDataUpdateOperation;

struct {
    ComponentID component_id;
    AppDataUpdateOperation op;

    select (AppDataUpdate.op) {
        case update: opaque update<V>;
        case remove: struct{};
    };
} AppDataUpdate;
~~~

An AppDataUpdate proposal is invalid if its `component_id` references a
component that is not known to the application, or if it specifies the removal
of state for a `component_id` that has no state present.  A proposal list is
invalid if it includes multiple AppDataUpdate proposals that `remove`
state for the same `component_id`, or proposals that both `update` and `remove`
state for the same `component_id`.  In other words, for a given `component_id`,
a proposal list is valid only if it contains (a) a single `remove` operation or
(b) one or more `update` operation.

AppDataUpdate proposals are processed after any default proposals (i.e., those
defined in {{RFC9420}}), and any AppEphemeral proposals (defined in
{{app-ephemeral}}).

When an MLS group contains the AppDataUpdate proposal type in the
`proposal_types` list in the group's `required_capabilities` extension, a
GroupContextExtensions proposal MUST NOT add, remove, or modify the
`app_data_dictionary` GroupContext extension. In other words, when every member of
the group supports the AppDataUpdate proposal, a GroupContextExtensions proposal
could be sent to update some other extension(s), but the `app_data_dictionary`
GroupContext extension, if it exists, is left as it was.

A commit can contain a GroupContextExtensions proposal which modifies
GroupContext extensions other than `app_data_dictionary`, and can be followed by
zero or more AppDataUpdate proposals.  This allows modifications to both the
`app_data_dictionary` extension (via AppDataUpdate) and other extensions (via
GroupContextExtensions) in the same Commit.

A client applies AppDataUpdate proposals by component ID.  For each
`component_id` field that appears in an AppDataUpdate proposal in the
Commit, the client assembles a list of AppDataUpdate proposals with that
`component_id`, in the order in which they appear in the Commit, and processes
them in the following way:

* If the list comprises a single proposal with the `op` field set to `remove`:

    * If there is an entry in the `component_states` vector in the
      `application_state` extension with the specified `component_id`, remove
      it.

    * Otherwise, the proposal is invalid.

* If the list comprises one or more proposals, all with `op` field set to
  `update`:

    * Provide the application logic registered to the `component_id` value with
      the content of the `update` field from each proposal, in the order
      specified.

    * The application logic returns either an opaque value `new_data` that will be
      stored as the new application data for this component, or else an
      indication that it considers this update invalid.

    * If the application logic considers the update invalid, the MLS client MUST
      consider the proposal list invalid.

    * If no `app_data_dictionary` extension is present in the GroupContext, add one
      to the end of the `extensions` list in the GroupContext.

    * If there is an entry in the `component_data` vector in the
      `app_data_dictionary` extension with the specified `component_id`, then set
      its `data` field to the specified `new_data`.

    * Otherwise, insert a new entry in the `component_states` vector with the
      specified `component_id` and the `data` field set to the `new_data`
      value.  The new entry is inserted at the proper point to keep the
      `component_states` vector sorted by `component_id`.

* Otherwise, the proposal list is invalid.

> NOTE: An alternative design here would be to have the `update` operation
> simply set the new value for the `app_data_dictionary` GCE, instead of sending a
> diff.  This would be simpler in that the MLS stack wouldn't have to ask the
> application for the new state value, and would discourage applications from
> storing large state in the GroupContext directly (which bloats Welcome
> messages).  It would effectively require the state in the GroupContext to be a
> hash of the real state, to avoid large AppDataUpdate proposals.  This
> pushes some complexity onto the application, since the application has to
> define a hashing algorithm, and define its own scheme for initializing new
> joiners.

AppDataUpdate proposals do not require an UpdatePath.
An AppDataUpdate proposal can be sent by an external sender. Likewise,
AppDataUpdate proposals can be included in an external commit. Applications
can make more restrictive validity rules for the update of their components,
such that some components would not be valid at the application when sent in
an external commit or via an external proposer.


## Attaching Application Data to a Commit {#app-ephemeral}

The AppEphemeral proposal type allows an application component to associate
application data to a Commit, so that the member processing the Commit knows
that all other group members will be processing the same data.  AppEphemeral
proposals are ephemeral in the sense that they do not change any persistent
state related to MLS, aside from their appearance in the transcript hash.

The content of an AppEphemeral proposal is the same as an `app_data_dictionary`
extension.  The proposal type is set in {{iana-considerations}}.

~~~ tls-presentation
struct {
    ComponentID component_id;
    opaque data<V>;
} AppEphemeral;
~~~

An AppEphemeral proposal is invalid if it contains a `component_id` that is
unknown to the application, or if the `app_data_dictionary` field contains any
`ComponentData` entry whose `data` field is considered invalid by the
application logic registered to the indicated `component_id`.

AppEphemeral proposals MUST be processed after any default proposals (i.e.,
those defined in {{RFC9420}}), but before any AppDataUpdate proposals.

A client applies an AppEphemeral proposal by providing the contents of the
`app_data_dictionary` field to the component identified by the `component_id`.  If
a Commit references more than one AppEphemeral proposal for the same
`component_id` value, then they MUST be processed in the order in which they are
specified in the Commit.

AppEphemeral proposals do not require an UpdatePath.
An AppEphemeral proposal can be sent by an external sender. Likewise,
AppEphemeral proposals can be included in an external commit. Applications
can make more restrictive validity rules for ephemeral updates of their
components, such that some components would not be valid at the application when
sent in an external commit or via an external proposer.


## Safe Additional Authenticated Data (AAD) {#safe-aad}

The `PrivateContentAAD` struct in MLS can contain arbitrary additional
application-specific AAD in its `authenticated_data` field. This API
defines a framing used to allow multiple extensions to add AAD safely
without conflicts or ambiguity.

When any AAD safe extension is included in the `authenticated_data` field,
the "safe" AAD items MUST come before any non-safe data in the
`authenticated_data` field. Safe AAD items are framed using the `SafeAAD`
struct and are sorted in increasing numerical order of the `component_id`.
The struct is described below:

~~~ tls-presentation
struct {
  ComponentID component_id;
  opaque aad_item_data<V>;
} SafeAADItem;

struct {
  SafeAADItem aad_items<V>;
} SafeAAD;
~~~

If the `SafeAAD` is present or not in the `authenticated_data` is determined by
the presence of the `safe_aad` component in the `app_data_dictionary` extension
in the GroupContext (see {{negotiation}}). If `safe_aad` is present, but none
of the "safe" AAD components have data to send in a particular message, the
`aad_items` is a zero-length vector.


# Negotiating Extensions and Components {#negotiation}

MLS defines a `Capabilities` struct for LeafNodes (in turn used in
KeyPackages), which describes which extensions are supported by the
associated node.
However, that struct (defined in {{Section 7.2 of !RFC9420}}) only has
fields for a subset of the extensions possible in MLS, as reproduced below.

~~~ tls-presentation
struct {
    ProtocolVersion versions<V>;
    CipherSuite cipher_suites<V>;
    ExtensionType extensions<V>;
    ProposalType proposals<V>;
    CredentialType credentials<V>;
} Capabilities;
~~~

> The "MLS Extensions Types" registry represents extensibility of four
  core structs (`GroupContext`, `GroupInfo`, `KeyPackage`, and `LeafNode`)
  that have far reaching effects on the use of the protocol. The majority of
  MLS extensions in {{!RFC9420}} extend one or more of these core structs.

Likewise, the `required_capabilities` GroupContext extension (defined
in {{Section 11.1 of !RFC9420}} and reproduced below) contains all
mandatory to support non-default extensions in its `extension_types` vector.
Its `proposal_types` vector contains any mandatory to support Proposals.
Its `credential_types` vector contains any mandatory credential types.

~~~
struct {
   ExtensionType extension_types<V>;
   ProposalType proposal_types<V>;
   CredentialType credential_types<V>;
} RequiredCapabilities;
~~~

Due to an oversight in {{!RFC9420}}, the Capabilities struct does not include
MLS Wire Formats. Instead, this document defines two extensions: `supported_wire_formats` (which can appear in LeafNodes), and
`required_wire_formats` (which can appear in the GroupContext).

~~~ tls-presentation
struct {
   WireFormat wire_formats<V>;
} WireFormats

WireFormats supported_wire_formats;
WireFormats requires_wire_formats;
~~~

This document also defines new components of the `app_data_dictionary`
extension for supported and required Safe AAD, media types, and components.

The `safe_aad` component contains a list of components IDs. When present (in an
`app_data_dictionary` extension) in a LeafNode, the semantic is the list of
supported components that use Safe AAD. When present (in an
`app_data_dictionary` extension) in the GroupContext, the semantic is the list
of required Safe AAD components (those that must be understood by the entire
group). If the `safe_aad` component is present, even with an empty list, (in the
`app_data_dictionary` extension) in the GroupContext, then the
`authenticated_data` field always starts with the SafeAAD struct defined in
{{safe-aad}}.

~~~ tls-presentation
struct {
    ComponentID component_ids<V>;
} ComponentsList;

ComponentsList safe_aad;
~~~

The list of required and supported components follows the same model with the
new component `app_components`. When present in a LeafNode, the semantic is the
list of supported components. When present in the GroupContext, the semantic is
the list of required components.

~~~ tls-presentation
ComponentsList app_components;
~~~

Finally, the supported and required media types (formerly called MIME types)
are communicated in the `content_media_types` component (see
{{content-advertisement}}).


# Extensions

## AppAck

An AppAck object is used to acknowledge receipt of application messages.
Though this information implies no change to the group, it is conveyed inside
an AppEphermeral Proposal with a component ID `app_ack`, so that it is included
in the group's transcript by being included in Commit messages.

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

An AppAck represents a set of messages received by the sender in the
current epoch.  Messages are represented by the `sender` and `generation` values
in the MLSCiphertext for the message.  Each MessageRange represents receipt of a
span of messages whose `generation` values form a continuous range from
`first_generation` to `last_generation`, inclusive.

AppAck objects are sent as a guard against the Delivery Service dropping
application messages.  The sequential nature of the `generation` field provides
a degree of loss detection, since gaps in the `generation` sequence indicate
dropped messages.  AppAck completes this story by addressing the scenario where
the Delivery Service drops all messages after a certain point, so that a later
generation is never observed.  Obviously, there is a risk that AppAck messages
could be suppressed as well, but their inclusion in the transcript means that if
they are suppressed then the group cannot advance at all.

The schedule on which AppAck objects are sent in AppEphemeral proposals is up to
the application,and determines which cases of loss/suppression are detected.
For example:

- The application might have the committer include an AppAck whenever a
  Commit is sent, so that other members could know when one of their messages
  did not reach the committer.

- The application could have a client send an AppAck whenever an application
  message is sent, covering all messages received since its last AppAck.  This
  would provide a complete view of any losses experienced by active members.

- The application could simply have clients send AppAck proposals on a timer, so
  that all participants' state would be known.

An application using AppAck to guard against loss/suppression of
application messages also needs to ensure that AppAck messages and the Commits
that reference them are not dropped.  One way to do this is to always encrypt
Proposal and Commit messages, to make it more difficult for the Delivery Service
to recognize which messages contain AppAcks.  The application can also have
clients enforce an AppAck schedule, reporting loss if an AppAck is not received
at the expected time.

> Note: External Commits do not typically contain pending proposals (including
> AppEphemeral proposals).

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
confidentiality and authentication, reusing mechanisms from {{!RFC9420}}, in
particular {{!RFC9180}}.

### Format

This extension uses the `mls_extension_message` WireFormat, where the content is a `TargetedMessage`.

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
`MLSSenderData` as described in {{Section 6.3.2 of !RFC9420}}. The
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

The functions `SealAuth` and `OpenAuth` defined in {{!RFC9180}} are used as
described in {{safe-hpke}} with an empty context. Other functions are defined in
{{!RFC9420}}.

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
{{Section 9.1.1 of !RFC9180}} beforehand.

## Content Advertisement

### Description

This section defines a minimal framing format so MLS clients can signal
which media type is being sent inside the MLS `application_data` object when
multiple formats are permitted in the same group.

It also defines a new `content_media_types` application component which is used to indicate support for specific formats, using the extensive IANA Media Types
registry (formerly called MIME Types). When the `content_media_types` component
is present (in the `app_data_dictionary` extension) in a LeafNode, it indicates
that node's support for a particular (non-empty) list of media types. When the
`content_media_types` component is present (in the `app_data_dictionary`
extension) in the GroupContext, it indicates a (non-empty) list of media types
that need to be supported by all members of that MLS group, *and* that the
`application_data` will be framed using the application framing format
described later in {{app-framing}}. This allows clients to confirm that all
members of a group can communicate.

>Note that when the membership of a group changes, or when the policy of the
 group changes, it is responsibility of the committer to insure that the
 membership and policies are compatible.

As clients are upgraded to support new formats they can use these extensions
to detect when all members support a new or more efficient encoding, or select
the relevant format or formats to send.

Vendor-specific media subtypes starting with `vnd.` can be registered with IANA
without standards action as described in {{?RFC6838}}. Implementations which
wish to send multiple formats in a single application message, may be interested
in the `multipart/alternative` media type defined in {{?RFC2046}} or may use or
define another type with similar semantics (for example using TLS Presentation
Language syntax {{!RFC8446}}).

>Note that the usage of IANA media types in general does not imply the usage of
 MIME Headers {{?RFC2045}} for framing.


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
    /* must contain at least one item */
    MediaType media_types<V>;
} MediaTypeList;

MediaTypeList content_media_types;
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
`content_media_types` component (in the `app_data_dictionary` extension)
in its LeafNodes, listing all the media types it can receive. As usual, the
client also includes `content_media_types` in the `app_components` list (in the
`app_data_dictionary` extension) and support for the `app_data_dictionary`
extension in its `capabilities.extensions` field in its LeafNodes (including
in LeafNodes inside its KeyPackages).

When creating a new MLS group for an application using this specification,
the group MAY include a `content_media_types` component (in the
`app_data_dictionary` extension) in the GroupContext. (The creating
client also includes its `content_media_types` component in its own
LeafNode as described in the previous paragraph.)

MLS clients SHOULD NOT add an MLS client to an MLS group with
`content_media_types` in its GroupContext unless the MLS client advertises it
can support all of the required MediaTypes.
As an exception, a client could be preconfigured to know that certain clients
support the required types. Likewise, an MLS client is already forbidden from
issuing or committing a GroupContextExtensions Proposal which introduces
required extensions which are not supported by all members in the resulting
epoch.

### Framing of application_data {#app-framing}

When an MLS group contains the `content_media_types` component (in the
`app_data_dictionary` extension) in its GroupContext, the `application_data`
sent in that group is interpreted as `ApplicationFraming` as defined below:

~~~ tls
  struct {
      MediaType media_type;
      opaque<V> application_content;
  } ApplicationFraming;
~~~

The `media_type` MAY be zero length, in which case, the media type of the
`application_content` is interpreted as the first MediaType specified in
the `content_media_types` component in the GroupContext.

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
is described using the TLS Presentation Language {{!RFC8446}} below (its content
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

{{Section 10 of !RFC9420}} details that clients are required to pre-publish
KeyPackages so that other clients can add them to groups asynchronously. It
also states that they should not be re-used:

> KeyPackages are intended to be used only once and SHOULD NOT be reused except
> in the case of a "last resort" KeyPackage (see Section 16.8). Clients MAY
> generate and publish multiple KeyPackages to support multiple cipher suites.

{{Section 16.8 of !RFC9420}} then introduces the notion of last-resort
KeyPackages as follows:

> An application MAY allow for reuse of a "last resort" KeyPackage in order to
> prevent denial-of-service attacks.

However, {{!RFC9420}} does not specify how to distinguish regular KeyPackages
from last-resort ones. The last_resort_key_package KeyPackage application
component defined in this section fills this gap and allows clients to specifically mark KeyPackages as KeyPackages of last resort that MAY be used
more than once in scenarios where all other KeyPackages have already been used.

The component allows clients that pre-publish KeyPackages to signal to the
Delivery Service which KeyPackage(s) are meant to be used as last resort
KeyPackages.

An additional benefit of using a component rather than communicating the
information out-of-band is that the component is still present in Add proposals.
Clients processing such Add proposals can authenticate that a KeyPackage is a
last-resort KeyPackage and MAY make policy decisions based on that information.

### Format

The purpose of the application component is simply to mark a given KeyPackage,
which means it carries no additional data.

As a result, a LastResort Extension contains the `component_id` with an empty
`data` field.

## Multi-Credentials

Multi-credentials address use cases where there might not be a single
credential that captures all of a client's authenticated attributes. For
example, an enterprise messaging client may wish to provide attributes both
from its messaging service, to prove that its user has a given handle in
that service, and from its corporate owner, to prove that its user is an
employee of the corporation. Multi-credentials can also be used in migration
scenarios, where some clients in a group might wish to rely on a newer type
of credential, but other clients haven't yet been upgraded.

New credential types `MultiCredential` and `WeakMultiCredential` are
defined as shown below. These credential types are indicated with
the values `multi` and `weak-multi` (see {{iana-creds}}).

~~~ tls-presentation
struct {
  CipherSuite cipher_suite;
  Credential credential;
  SignaturePublicKey credential_key;

  /* SignWithLabel(., "CredentialBindingTBS", CredentialBindingTBS) */
  opaque signature<V>;
} CredentialBinding

struct {
  CredentialBinding bindings<V>;
} MultiCredential;

struct {
  CredentialBinding bindings<V>;
} WeakMultiCredential;
~~~

The two types of credentials are processed in exactly the same way.  The only
difference is in how they are treated when evaluating support by other clients,
as discussed below.

## Credential Bindings

A multi-credential consists of a collection of "credential bindings".  Each
credential binding is a signed statement by the holder of the credential that
the signature key in the LeafNode belongs to the holder of that credential.
Specifically, the signature is computed using the MLS `SignWithLabel` function,
with label `"CredentialBindingTBS"` and with a content that covers the contents
of the CredentialBinding, plus the `signature_key` field from the LeafNode in
which this credential will be embedded.

~~~ tls-presentation
struct {
  CipherSuite cipher_suite;
  Credential credential;
  SignaturePublicKey credential_key;
  SignaturePublicKey signature_key;
} CredentialBindingTBS;
~~~

The `cipher_suite` for a credential is NOT REQUIRED to match the cipher suite
for the MLS group in which it is used, but MUST meet the support requirements
with regard to support by group members discussed below.

## Verifying a Multi-Credential

A credential binding is supported by a client if the client supports the
credential type and cipher suite of the binding.  A credential binding is valid
in the context of a given LeafNode if both of the following are true:

* The `credential` is valid according to the MLS Authentication Service.

* The `credential_key` corresponds to the specified `credential`, in the same
  way that the `signature_key` would have to correspond to the credential if
  the credential were presented in a LeafNode.

* The `signature` field is valid with respect to the `signature_key` value in
  the leaf node.

A client that receives a credential of type `multi` in a LeafNode MUST verify
that all of the following are true:

* All members of the group support credential type `multi`.

* For each credential binding in the multi-credential:

  * Every member of the group supports the cipher suite and credential type
    values for the binding.

  * The binding is valid in the context of the LeafNode.

A client that receives a credential of type `weak-multi` in a LeafNode MUST verify
that all of the following are true:

* All members of the group support credential type `weak-multi`.

* Each member of the group supports at least one binding in the
  multi-credential.  (Different members may support different subsets.)

* Every binding that this client supports is valid in the context of the
  LeafNode.


# IANA Considerations

This document requests the addition of various new values under the heading
of "Messaging Layer Security".  Each registration is organized under the
relevant registry Type.

This document also requests the creation of a new MLS applications components
registry as described in {{iana-components}}.

RFC EDITOR: Please replace XXXX throughout with the RFC number assigned to
this document

## MLS Wire Formats

### MLS Targeted Message

The `mls_targeted_message` MLS Wire Format is used to send a message
to a subset of members of an MLS group.

 * Value: 0x0006 (suggested)
 * Name: mls_targeted_message
 * Recommended: Y
 * Reference: RFC XXXX


## MLS Extension Types

### app_data_dictionary MLS Extension

The `app_data_dictionary` MLS Extension Type is used inside KeyPackage,
LeafNode, GroupContext, or GroupInfo objects. It contains a sorted list of
application component data objects (at most one per component).

* Value: 0x0006 (suggested)
* Name: app_data_dictionary
* Message(s): KP: This extension may appear in KeyPackage objects
              LN: This extension may appear in LeafNode objects
              GC: This extension may appear in GroupContext objects
              GI: This extension may appear in GroupInfo objects
* Recommended: Y
* Reference: RFC XXXX

### supported_wire_formats MLS Extension

The `supported_wire_formats` MLS Extension Type is used inside LeafNode
objects. It contains a list of non-default Wire Formats supported by the
client node.

* Value: 0x0007 (suggested)
* Name: supported_wire_formats
* Message(s): LN: This extension may appear in LeafNode objects
* Recommended: Y
* Reference: RFC XXXX

### required_wire_formats MLS Extension

The `required_wire_formats` MLS Extension Type is used inside GroupContext
objects. It contains a list of non-default Wire Formats that are mandatory for
all MLS members of the group to support.

* Value: 0x0008 (suggested)
* Name: required_wire_formats
* Message(s): GC: This extension may appear in GroupContext objects
* Recommended: Y
* Reference: RFC XXXX

### targeted_messages_capability MLS Extension

The `targeted_messages_capability` MLS Extension Type is used in the
`capabilities.extensions` field of LeafNodes to indicate the support for the
Targeted Messages Extension, and in the `required_capabilities.extension_types`
field of the GroupContext to indicate all members of the group must support it.
The extension does not carry any payload.

* Value: 0x0009 (suggested)
* Name: targeted_messages_capability
* Message(s): LN: This extension may appear in LeafNode objects
              GC: This extension may appear in GroupContext objects
* Recommended: Y
* Reference: RFC XXXX


## MLS Proposal Types

### AppDataUpdate Proposal

The `app_data_update` MLS Proposal Type is used to efficiently update
application component data stored in the `app_data_dictionary` GroupContext
extension.

* Value: 0x0008 (suggested)
* Name: app_data_update
* Recommended: Y
* External: Y
* Path Required: N

### AppEphemeral Proposal
 The `app_ephemeral` MLS Proposal Type is used to send opaque ephemeral
 application data that needs to be synchronized with a specific MLS epoch.

* Value: 0x0009 (suggested)
* Name: app_ephemeral
* Recommended: Y
* External: Y
* Path Required: N

### SelfRemove Proposal

The `self_remove` MLS Proposal Type is used for a member to remove itself
from a group more efficiently than using a `remove` proposal type, as the
`self_remove` type is permitted in External Commits.

* Value: 0x0008 (suggested)
* Name: self_remove
* Recommended: Y
* External: N
* Path Required: Y

## MLS Credential Types {#iana-creds}

### Multi Credential

* Value: 0x0003 (suggested)
* Name: multi
* Recommended: Y
* Reference: RFC XXXX

### Weak Multi Credential

* Value: 0x0004
* Name: weak-multi
* Recommended: Y
* Reference: RFC XXXX

<!-- ## MLS Signature Labels

### Labeled Extension Content

* Label: "LabeledExtensionContent" (suggested)
* Recommended: Y
* Reference: RFC XXXX -->

## MLS Component Types {#iana-components}

This document requests the creation of a new IANA "MLS Component Types" registry under the "Messaging Layer Security" group registry heading. Assignments to this registry in the range 0x0000 0000 to 0x7FFF FFFF are via Specification Required
policy {{!RFC8126}} using the MLS Designated Experts. Assignments in the range
0x8000 0000 to 0xFFFF FFFF are for private use.

Template:
- Value: The numeric value of the component ID
- Name: The name of the component
- Where: The objects(s) in which the component may appear,
         drawn from the following list:
    - AD: SafeAAD objects
    - AE: AppEpheral proposals
    - ES: Exporter Secret labels
    - GC: GroupContext objects
    - GI: GroupInfo objects
    - HP: HPKE key labels
    - KP: KeyPackage objects
    - LN: LeafNode objects
    - PS: PSK labels
    - SK: Signature Key labels
- Recommended: Same as in {{Section 17.1 of !RFC9420}}
- Reference: The document where this component is defined

The restrictions noted in the "Where" column are to be enforced by the
application.  MLS implementations MUST NOT impose restrictions on where
component IDs are used in which parts of MLS, unless specifically directed to by
the application.

Initial Contents:

| Value         | Name                     | Where | R | Ref     |
|---------------+--------------------------+-------+---+---------|
| 0x0000 0000   | RESERVED                 | N/A   | - | RFCXXXX |
| 0x0000 0001   | app_components           | LN,GC | Y | RFCXXXX |
| 0x0000 0002   | safe_aad                 | LN,GC | Y | RFCXXXX |
| 0x0000 0003   | content_media_types      | LN,GC | Y | RFCXXXX |
| 0x0000 0004   | last_resort_key_package  | KP    | Y | RFCXXXX |
| 0x0000 0005   | app_ack                  | AE    | Y | RFCXXXX |
| 0x8000 0000 -
  0xFFFF FFFF   | Reserved for Private Use | N/A   | N | RFCXXXX |


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


## Multi Credentials

Using a Weak Multi Credential reduces the overall credential security to the
security of the least secure of its credential bindings.

--- back

# Change Log

RFC EDITOR PLEASE DELETE THIS SECTION.

draft-06

- Integrate notion of Application API from draft-barnes-mls-appsync

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

# Old Safe Extensions Text

The MLS specification is extensible in a variety of ways (see {{Section 13 of
!RFC9420}}) and describes the negotiation and other handling of extensions and
their data within the protocol. However, it does not provide guidance on how
extensions can or should safely interact with the base MLS protocol. The goal of
this section is to simplify the task of developing MLS extensions.


## Security

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


## Extension state: anchoring, storage and agreement

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
extension using an extension-defined proposal (see ). The semantics
of the proposal determines how the state is changed.

The `read` variable determines the permissions that other MLS extensions have
w.r.t. the data stored within. `read` allows other MLS extensions to read that
data via their own proposals, while `none` marks the data as private to the
owning MLS extension.

Other extensions may never write to the `ExtensionState` of the owning MLS
extension.

### Direct vs. hash-based storage

Storing the data directly in the `ExtensionState` means the data becomes part of
the group state. Depending on the application design, this can be advantageous,
because it is distributed via Welcome messages. However, it could also mean that
the data is visible to the delivery service. Additionally, if the application
makes use of GroupContextExtension proposals, it may be necessary to send all of
the data with each such extension.

Including the data by hash only allows group members to agree on the data
indirectly, relying on the collision resistance of the associated hash function.
The data itself, however, may have to be transmitted out-of-band to new joiners.

## Extension Design Guidance

While extensions can modify the protocol flow of MLS and the associated
properties in arbitrary ways, the base MLS protocol already enables a number of
functionalities that extensions can use without modifying MLS itself. Extension
authors should consider using these built-in mechanisms before employing more
intrusive changes to the protocol.
