# UnAuthZ: A Model for Place-Scoped Authorization with Guaranteed Recoverability

Status: working draft, not yet versioned, first committed 2026-11-04. Author: Sandro Circi. Licensed under the MIT licence. Sections marked "TBD" are not written yet.

## Abstract

UnAuthZ is a model that grounds authorization implementations of any sort and size, from a flat set of roles in a single application to multi-tenant platforms that share resources with guests. It defines how a set of stored statements answers "may this subject perform this permission at this place?", how the answers can be carried and verified away from the statements, and how changes to the statements are governed so that no permission can be escalated and no place can be left without someone able to recover it. The application defines the goal. The model defines the how. A library implementing it provides the tools. The model is independent of any programming language, storage system or transport.

## 1. Introduction

TBD. Content already settled for this section:

This document specifies the UnAuthZ model. It defines the statements an application keeps about its subjects, how those statements answer a question, how the answers are carried as grants, and how changes to the statements are governed. It does not define how statements are laid out in storage, how parties communicate, or any programming interface. Those belong to the application, to the store it provides, and to companion documents that bind the model to a language or a platform.

## 2. Conventions and notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/info/bcp14) [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

Wire formats (place keys, the grants payload, the version string) are given in ABNF [RFC5234] in [Appendix C](#appendix-c-abnf). Procedures are given in the pseudocode notation of [Appendix B](#appendix-b-pseudocode-notation). Examples are JSON [RFC8259] or plain prose; they are illustrative and never normative.

## 3. Terminology

A **permission** is one action on one kind of resource, written `resource:action`, for example `event:manage`. A permission says what, it never says where. The reserved token `*` is a **wildcard**: in place of the resource, the action or both, it stands for every value the catalog has there. [Section 5](#5-catalog) defines how wildcards resolve and where they are legal.

A **catalog** is the closed list of permissions an application recognises, together with its **implications**: a permission MAY imply others (`event:manage` implies `event:read`). An implication only adds. Nothing in a catalog denies.

A **place** is where a statement applies: a position in a path that starts at the single, unnamed **root** and continues through typed **segments**. A segment pairs a **level**, a kind of place the application declared such as `org` or `unit`, with a value the application assigns to name which org, which unit, and that the model compares only for equality. The **structure** is the application's declaration of its levels and of which level may sit under which. The **key** is the string form of a place, for example `/org/org-1/unit/u7`; the root's key is `/`. One place **covers** another when a statement placed at the first applies at the second, and is **wider** than it when it covers it and is not the same place. The **chain** of a place is the ordered list of the places covering it, from the place itself up to the root. [Section 6](#6-place) defines the structure, the key syntax and how coverage is computed.

A **subject** is whom a statement is about: the application's own identifier for a user, an application or a machine. It has the meaning of the `sub` claim in JSON Web Token (JWT) [RFC7519].

A **statement** is one stored assertion about one subject at one place. There are two kinds:

- A **rule** is a personal allow or deny of one permission: `{ subject, permission, place, effect, expiresAt? }` with `effect` one of `allow`, `deny`. A rule is the only kind of statement that can deny.
- An **assignment** is a role held by a subject: `{ subject, role, place, expiresAt? }`. An assignment only ever adds.

A statement is **live** at a given time when it has no `expiresAt` or `expiresAt` is later than that time. A statement with no `expiresAt` is **permanent**.

A **role** is a named list of **entries**, defined once and independent of any place. An entry names a permission, names another role, or, prefixed with `-`, is an **exclusion** that removes what it names from what the other entries give. The same role can be assigned at many places. A role defined in code is a **preset**. A role defined in data is a **stored role**. A role only ever adds to what a subject may do; a rule, not a role, is how a permission is denied. [Section 7](#7-decision) defines how a role resolves to permissions.

A **question** is one permission at one **target** place: "may Alice `event:manage` at `/org/org-1`?". A **decision** is the answer to a question together with its reason: allowed or not, and which statement determined it ([Section 7](#7-decision)).

A subject's **grants** are what the subject's statements amount to, written in a form that can be carried outside the statements and read without them. A **grant** is one entry of that form: what the statements sitting at one place allow the subject and what they deny. Grants repeat nothing that the chain already gives, so what a subject may do at a place is derived when grants are read, not written into them. A statement is stored, grants are carried. [Section 8](#8-grants) defines their format, how they are read and when they must be reissued.

A **manager** of a place is a subject who may change the statements there: place or remove a statement about a subject, or edit a stored role. A subject is a manager of a place by holding, at that place or at a wider one, the permission the catalog designates for it ([Section 5](#5-catalog)). Only a manager of a place may change the statements there. A manager is a subject whenever their own permissions are checked. A manager through a permanent statement at the root is a **permanent manager**.

**Genesis** is the first permanent allow rule of `*` placed at the root while it has no manager yet. It is the only change to the statements performed by someone who is not a manager, and it is possible only while the root has no manager.

This document addresses three parties. An **engine** is software that computes according to this document: it resolves roles, answers questions, issues and reads grants, and checks who may change statements. An engine keeps no statements. A **store** is software that keeps statements and applies changes to them; the application provides it, and [Section 9](#9-sources-of-answers) states what the model requires of it. The **application** is the software using an engine and a store: it defines the catalog and the structure, chooses where grants are carried, and decides who performs genesis. Everything this document leaves to the application is outside the model.

TBD: the terms for how an engine obtains answers and statements from a store, defined with [Section 9](#9-sources-of-answers); the term for the record of changes to the statements, defined with [Section 10](#10-authority).

## 4. Invariants

TBD. One table restating what the decision procedure guarantees, the rules on changing statements, and what those rules guarantee together. Working copy in [`invariants.md`](invariants.md). Content already settled for this section:

Permissions, place keys and grants each have exactly one canonical text form, defined in this document. That form is the only one an engine reads or writes. Any other representation that a store, an application or a carrier uses, a column layout, a numeric id, a compressed token, MUST round-trip to the canonical form without loss, so that two things are equal exactly when their canonical forms are equal. This is what lets grants fit a size-constrained carrier such as a cookie-borne token without the model knowing about carriers at all.

## 5. Catalog

TBD. Content already settled for this section:

A permission not in the catalog is unknown. An engine MUST refuse it wherever it appears: in a rule, in a role entry, in a question.

A catalog MAY designate one of its permissions as the one that makes its holder a manager. It is an ordinary permission, named as the application likes: this document reserves no permission name. A catalog is valid without it, since answering questions and issuing grants do not need it. An engine MUST refuse every change to the statements when the catalog designates none.

The wildcard `*` MAY stand for the resource (`*:read`), for the action (`event:*`) or for both, and a bare `*` is the short form of `*:*`. A wildcard resolves, at the time of the check, to every value the catalog has for that segment, so a catalog that grows is covered without a new write. Wildcards are legal in rules and in role entries, never in a question. No other pattern is recognised.

## 6. Place

TBD. Content already settled for this section:

There is exactly one root. It has no segment, and its key is `/`. The structure declares the level names and the nesting edges: which level may sit directly under the root, and which under which other level. A level MAY have several child levels, MAY have several parent levels, and MAY nest under itself, so depth is unbounded unless the structure declares a maximum. Whatever the structure, places form a tree: a place has exactly one parent, obtained by dropping its last segment. Whether a given place exists, whether `org-1` is a real tenant, is not part of the model; the application answers that before it calls the engine. Segments under the same parent have no order among themselves: `org-1` and `org-2` are different orgs, not a first and a second.

A key writes the root as `/` and every segment as `/level/value`, level and value alternating: `/org/org-1/unit/u7`. Alternation is chosen so that no character beyond `/` is claimed from values: a value MAY contain `:` and other characters that specifications or applications give meaning to, such as a decentralized identifier. [Appendix C](#appendix-c-abnf) gives the grammar. A value is written with percent-encoding as in [RFC3986], uppercase hexadecimal, and only for the bytes that require it, so that one place has exactly one spelling. The values `*`, `.` and `..` are reserved and MUST NOT be used. A key is either canonical or refused: an engine MUST NOT accept a key that is not in canonical form, and MUST NOT normalise one into it.

A value is matched by equality only. No pattern or prefix matching exists on values: two patterns could cover one target without covering each other, and the places covering a target would no longer form a chain. An application that wants one place to cover a family of values declares the family as a level and builds the key accordingly, for example `/family/shop/app/shop-preview`, so that a statement at `/family/shop` covers every shop application by plain coverage. The key is the model's text for a place in questions, in grants and in records. A store MAY represent a place any way it likes, provided it yields the identical key back.

Example: a structure declares `org` under the root, and `unit` and `project` under `org`. The places `/org/org-1/unit/u7` and `/org/org-1/project/p3` both sit under `/org/org-1`, and the level in each segment tells a unit from a project even when their values collide.

### 6.1. Coverage

A place covers itself and every place below it. The procedure takes two keys, `S` where a statement sits and the target `T` of a question, and answers whether `S` covers `T`.

```
covers(S, T):
  if S == "/":                 return true
  if T == S:                   return true
  if T starts with S + "/":    return true
  return false
```

The chain of `T` is `T`, then `T` with its last segment dropped, and so on up to `/`. The places covering `T` are exactly its chain, so they are totally ordered from `T` up to the root. This order is what makes "strictly wider than" well defined wherever later sections use it. In the example, the chain of `/org/org-1/unit/u7` is itself, `/org/org-1` and `/`. Something like `/org/org-2` does not cover it, because the segments differ, and `/org/org-1/unit/u7` does not cover `/org/org-1`, because it is longer. Coverage is the only ordering the model knows. There is no other grouping of subjects or places.

## 7. Decision

TBD. Content already settled for this section:

### 7.1. Role resolution

A role entry is read as follows: an entry containing `:` names a permission, possibly with wildcards; an entry prefixed with `-` is an exclusion of what follows the prefix; any other entry names a role. The `-` prefix is legal only inside a role definition. The order of entries carries no meaning. An exclusion that removes nothing has no effect. Example: `support = ["*:read", "-billing:read"]` reads everything except billing.

A role that names another role receives what the named role gives, and the named role's exclusions keep applying unless the referencing role names the excluded permission itself, by an exact entry or by a wildcard. Example: `["support", "billing:read"]` reads billing, while `["support", "moderator"]` does not, whatever `moderator` holds. A preset MAY reference presets only. A stored role MAY reference presets and stored roles.

A role `R` resolves to two sets of concrete permissions: `P`, what the role gives, and `E`, what the role still forbids to roles that reference it. Before resolution every wildcard in the role's own entries is expanded against the catalog in force, so the procedure works on plain sets. `own_includes(R)` are the role's own entries that name a permission, `own_excludes(R)` its own exclusions, and `refs(R)` the roles it names. `P(ref)` and `E(ref)` are the two sets of a referenced role, computed by the same procedure.

```
resolve(R):
  P_in = union of P(ref) for every ref in refs(R)
  E_in = union of E(ref) for every ref in refs(R)
  P    = ((P_in minus E_in) union own_includes(R)) minus own_excludes(R)
  E    = (E_in minus own_includes(R)) union own_excludes(R)
  return (P, E)
```

A role with no references has `P_in` and `E_in` empty, so `P` is its includes minus its excludes. Every other part of the model that reads a role reads `P` only: the check, the authority rules, the issuing of grants. `E` is consumed by resolution alone. An engine MUST refuse a reference to an unknown role, and a cycle of references, when the role is defined, so `resolve` always terminates.

## 8. Grants

TBD. Content already settled for this section:

Grants are carried where the application chooses, for example in a session token or in a server-side session record. The place is the application's choice, the format is normative. An application MAY issue grants for the whole tree or for one place and what lies under it.

Grants carry no redundant information. A grant holds only what the statements sitting at its own place give: the permissions allowed there and the permissions denied there. A permission that comes from a wider place is written once, in the grant of that place, and never repeated in the grants below it.

A wildcard is carried as it was written, not expanded: the catalog fingerprint in the version of the grants pins its meaning, and a changed catalog forces a reissue. An assignment of a preset is carried as the name of the preset, which an engine resolves from the presets it already has. An assignment of a stored role is carried as the permissions that role resolves to when the grants are issued, so that reading grants never requires a store.

A question is answered from grants by walking the chain of the target: it is allowed when some grant on the chain allows the permission and no grant on the chain denies it. This is the decision rule of [Section 7](#7-decision) applied to grants, so grants and statements agree by construction. Reading needs the grants at the keys of the chain and nothing else.

## 9. Sources of answers

TBD. Content already settled for this section:

What the model requires of a store, and nothing more: a store MUST look up the statements of a subject at a place by exact key, for every key of a chain; it MUST keep a statement at the place the engine gave; and whatever form it keeps permissions, places and statements in, what it hands back MUST be the canonical form, as [Section 4](#4-invariants) requires. The lifecycle of statements whose place no longer exists in the application is the application's business: the engine never asks whether a place exists, so such a statement is garbage, not an error. Listing the places under a given one is useful to administration interfaces and MAY be offered; the engine never requires it.

## 10. Authority

TBD.

## 11. Errors

TBD.

## 12. Security considerations

TBD. Content already settled for this section:

The model does not restrict which subjects a manager may place statements about. A manager of a place may place an allow for any subject there, bounded by what the manager holds, and a deny for any subject, bounded by the rules on restrictions. In practice an application often wants a narrower circle, for example only the members of a team or the users of a tenant. That notion of membership is the application's, not the model's: the model knows no grouping of subjects other than the statements themselves. Applications SHOULD therefore constrain, before calling the engine, which subjects a manager may place statements about, and SHOULD treat the resulting refusal as their own, not as a decision of the model.

A deny restricts an identity, not content. A subject denied a permission still obtains whatever the application serves without identification, by asking from another browser, another device or another network. An application that needs content kept from someone MUST NOT serve that content to requests that do not identify themselves.

## 13. References

Citations in the text, such as [RFC2119], link to the documents below.

- [RFC2119]: Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, March 1997.
- [RFC8174]: Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, May 2017.
- [RFC3986]: Berners-Lee, T., Fielding, R. and L. Masinter, "Uniform Resource Identifier (URI): Generic Syntax", STD 66, RFC 3986, January 2005.
- [RFC5234]: Crocker, D. and P. Overell, "Augmented BNF for Syntax Specifications: ABNF", STD 68, RFC 5234, January 2008.
- [RFC7519]: Jones, M., Bradley, J. and N. Sakimura, "JSON Web Token (JWT)", RFC 7519, May 2015.
- [RFC8259]: Bray, T., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, RFC 8259, December 2017.

## Appendix A. Worked example: Roma

TBD.

## Appendix B. Pseudocode notation

TBD.

## Appendix C. ABNF

TBD.

[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC5234]: https://www.rfc-editor.org/rfc/rfc5234
[RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
[RFC8259]: https://www.rfc-editor.org/rfc/rfc8259
[RFC3986]: https://www.rfc-editor.org/rfc/rfc3986
