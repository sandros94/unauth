# UnAuthZ: A Model for Place-Scoped Authorization with Guaranteed Recoverability

Status: working draft, not yet versioned, first committed 2026-11-04. Author: Sandro Circi. Licensed under the MIT licence. Sections marked "TBD" are not written yet.

## Abstract

UnAuthZ is a model that grounds authorization implementations of any sort and size, from a flat set of roles in a single application to multi-tenant platforms that share resources with guests. It defines how a set of stored statements answers "may this subject perform this permission at this place?", how the answers can be carried and verified away from the statements, and how changes to the statements are governed so that no permission can be escalated and no place can be left without someone able to recover it. The application defines the goal. The model defines the how. A library implementing it provides the tools. The model is independent of any programming language, storage system or transport.

## 1. Introduction

TBD. Content already settled for this section:

This document specifies the UnAuthZ model. It defines the statements an application keeps about its subjects, how those statements answer a question, how the answers are carried as grants, and how changes to the statements are governed. It does not define how statements are laid out in storage, how parties communicate, or any programming interface. Those belong to the application, to the store it provides, and to companion documents that bind the model to a language or a platform.

## 2. Conventions and notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/info/bcp14) [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

Wire formats (place keys, the grants payload, the version string) are given in ABNF [RFC5234] in [Appendix C](#appendix-c-abnf). Procedures are given in the pseudocode notation of [Appendix B](#appendix-b-pseudocode-notation). Examples are JSON [RFC8259] or plain prose, they are illustrative and never normative.

## 3. Terminology

A **permission** is one action on one kind of resource, written `resource:action`, for example `event:manage`. A permission says what, it never says where. The reserved token `*` is a **wildcard**: in place of the resource, the action or both, it stands for every value the catalog has there. [Section 5](#5-catalog) defines how wildcards resolve and where they are legal.

A **catalog** is the closed list of permissions an application recognises, together with its **implications**: a permission MAY imply others (`event:manage` implies `event:read`), meaning that it includes them. Holding the implying permission satisfies the implied one, a deny of the implied one reaches every permission that implies it ([Section 5.1](#51-implications)). Nothing in a catalog denies by itself.

A **place** is where a statement applies: a position in a path that starts at the single, unnamed **root** and continues through typed **segments**. A segment pairs a **level**, a kind of place the application declared such as `org` or `unit`, with a value the application assigns to name which org, which unit, and that the model compares only for equality. The **structure** is the application's declaration of its levels and of which level may sit under which. The **key** is the string form of a place, for example `/org/org-1/unit/u7`, the root's key is `/`. One place **covers** another when a statement placed at the first applies at the second, and is **wider** than it when it covers it and is not the same place. The **chain** of a place is the ordered list of the places covering it, from the place itself up to the root. [Section 6](#6-place) defines the structure, the key syntax and how coverage is computed.

A **subject** is whom a statement is about: an identifier the application chooses. For a single user, application or machine it has the meaning of the `sub` claim in JSON Web Token (JWT) [RFC7519]. The application may also choose an identifier for a **group** of them, such as the members of an organisation or a team. Which subjects belong to a group is a fact the application keeps and supplies, never one the model derives. A statement about a group applies to every subject the application says belongs to it, except a deny, which applies to a single subject only ([Section 7](#7-decision)).

A **statement** is one stored assertion about one subject at one place. Every statement has the same shape, `{ kind, subject, value, place?, expiresAt? }`, and `kind` names what it asserts:

- `allow`: makes the subject hold the permission in `value` at the place.
- `assign`: makes the subject hold the role named in `value` at the place. An assignment only ever adds.
- `deny`: blocks the subject from the permission in `value` at the place, whatever gives it. A deny is the only kind that blocks, and it never names a group ([Section 7](#7-decision)).
- `exclude`: takes the permission in `value` out of what the subject's own statements at wider places give at this place ([Section 7](#7-decision)). An exclusion narrows the reach of those statements and touches nothing else.

`value` is a permission, with wildcards allowed, for `allow`, `deny` and `exclude`, and a role name for `assign`. `place` MAY be absent: an absent place is the root, so an application without places writes none.

A statement is **live** at a given time when it has no `expiresAt` or `expiresAt` is later than that time. A statement with no `expiresAt` is **permanent**.

A **role** is a named list of **entries**, defined once and independent of any place. An entry names a permission, names another role, or, prefixed with `-`, is an **exclusion** that removes what it names from what the other entries give. The same role can be assigned at many places. A role defined in code is a **preset**. A role defined in data is a **stored role**. A role only ever adds to what a subject may do. A deny statement blocks a subject from a permission, an exclusion takes a permission out of what a source gives. [Section 7](#7-decision) defines how a role resolves to permissions.

A **question** is one permission at one **target** place, asked for a subject together with the groups the application says it belongs to: "may Alice, a member of `acme-team`, `event:manage` at `/org/org-1`?". A **decision** is the answer to a question together with its reason: allowed or not, and which statement determined it ([Section 7](#7-decision)).

A subject's **grants** are what the statements about the subject and about its groups amount to, written in a form that can be carried outside the statements and read without them. A **grant** is one entry of that form: what the statements sitting at one place allow the subject and what they deny. Grants repeat nothing that the chain already gives, so what a subject may do at a place is derived when grants are read, not written into them. A statement is stored, grants are carried. Grants are issued for one or more **bases**, places under which they answer. A target under no base is **not covered**, and a read says so instead of answering. [Section 8](#8-grants) defines their format, how they are read and when they must be reissued.

A **manager** of a place is a subject who may change the statements there: place or remove a statement about a subject, or edit a stored role. A subject is a manager of a place by holding, at that place or at a wider one, the permission the catalog designates for it ([Section 5](#5-catalog)). Only a manager of a place may change the statements there. A manager is a subject whenever their own permissions are checked. A subject who is a manager through a permanent statement about the subject itself at the root is a **permanent manager**. A statement about a group never makes a permanent manager, since an engine cannot see who belongs to a group.

**Genesis** is the first permanent allow of `*` placed at the root while it has no manager yet. It is the only change to the statements performed by someone who is not a manager, and it is possible only while the root has no manager.

This document addresses three parties. An **engine** is software that computes according to this document: it resolves roles, answers questions, issues and reads grants, and checks who may change statements. An engine keeps no statements. A **store** is software that keeps statements and applies changes to them, the application provides it and [Section 9](#9-sources-of-answers) states what the model requires of it. The **application** is the software using an engine and a store: it defines the catalog and the structure, chooses where grants are carried, and decides who performs genesis. Everything this document leaves to the application is outside the model.

TBD: the terms for how an engine obtains answers and statements from a store, defined with [Section 9](#9-sources-of-answers); the term for the record of changes to the statements, defined with [Section 10](#10-authority).

## 4. Invariants

TBD. One table restating what the decision procedure guarantees, the rules on changing statements, and what those rules guarantee together. Working copy in [`invariants.md`](invariants.md). Content already settled for this section:

Permissions, place keys and grants each have exactly one canonical text form, defined in this document. That form is the only one an engine reads or writes. Any other representation that a store, an application or a carrier uses, a column layout, a numeric id, a compressed token, MUST round-trip to the canonical form without loss, so that two things are equal exactly when their canonical forms are equal. This is what lets grants fit a size-constrained carrier such as a cookie-borne token without the model knowing about carriers at all.

## 5. Catalog

TBD. Content already settled for this section:

A permission not in the catalog is unknown. An engine MUST refuse it wherever it appears: in a rule, in a role entry, in a question.

A catalog MAY designate one of its permissions as the one that makes its holder a manager. It is an ordinary permission, named as the application likes: this document reserves no permission name. A catalog is valid without it, since answering questions and issuing grants do not need it. An engine MUST refuse every change to the statements when the catalog designates none.

The wildcard `*` MAY stand for the resource (`*:read`), for the action (`event:*`) or for both, and a bare `*` is the short form of `*:*`. A wildcard resolves, at the time of the check, to every value the catalog has for that segment, so a catalog that grows is covered without a new write. Wildcards are legal in rules and in role entries, never in a question. No other pattern is recognised.

### 5.1. Implications

An implication is declared in the catalog, from one permission to another: `report:write` implies `report:read`, since writing a report means reading it first. It means that the first permission includes the second: whoever holds `report:write` also satisfies a question about `report:read`. Implications are transitive, a permission may imply several others and be implied by several others, and both permissions of an implication MUST exist in the catalog.

Because the implying permission includes the implied one, a deny reaches downward along implications: a deny of a permission also denies every permission that implies it, directly or through a chain, since exercising any of those would exercise the denied one. A deny never reaches upward: denying `report:write` leaves `report:read` as it was. An exclusion in a role removes the permissions it names and every permission that implies them, for the same reason: the role `["*:*", "-report:read"]` yields neither `report:read` nor `report:write`. A deny and an exclusion both reach what includes the named permission. They differ in what the named permission itself gave: an exclusion removes the permission from the role, so nothing it implied is given by that role any more, while a deny refuses the action and leaves what the permission implied as it was.

Example. Catalog: `report:list`, `report:read`, `report:write`, with `report:write` implying `report:read` and `report:read` implying `report:list`. One role, `analyst = ["report:write"]`, for staff who write their own reports, resolved as [Section 7.1](#71-role-resolution) describes. Alice and Bob are both assigned `analyst` at `/org/acme`, Bob also holds a deny of `report:read` there.

| Question at `/org/acme/report/q3` | Alice | Bob |
| --- | --- | --- |
| `report:write` | **allowed**: `analyst` gives it | **denied**: writing would read, and the deny reaches down to it |
| `report:read` | **allowed**: `report:write` implies it | **denied**: the deny names it |
| `report:list` | **allowed**: through the chain | **allowed**: listing does not read, so the deny does not reach up to it |

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

A question carries a subject and its groups. A statement applies to the question when its subject equals the subject or any of those groups, with one exception: a deny applies only when its subject equals the subject itself. A deny written about a group therefore has no effect, and an application SHOULD NOT write one. The identifiers are supplied by the application, an engine takes them as given and infers nothing about who belongs to what.

A question is answered in two steps, from the live statements at the places covering the target.

First, what is given. Each allow and each assignment about the subject or one of its groups gives a set of permissions: what the permission of an allow expands to, or what the role of an assignment resolves to ([Section 7.1](#71-role-resolution)). An exclusion about the same subject or group takes out of that set the permission it names and every permission that implies it, but only from statements placed at places wider than the exclusion's own, and only for targets at or under the exclusion's place.

Second, the denies. If a deny about the subject itself names the asked permission, or a permission the asked one implies ([Section 5.1](#51-implications)), the answer is denied, whatever was given. A deny MAY name a wildcard: it then blocks every permission the wildcard expands to, so a deny of `*` at a place blocks the subject from everything at and under that place. Otherwise the answer is allowed when some permission left is the asked one or implies it, and denied when none is.

Width never ranks statements, it orders the walk. Read the chain from the root down to the target, carrying for the subject and for each of its groups what has been given so far. At each place, first take out what the exclusions there remove from what that same subject or group carried in, then add what the allows and assignments there give. At the target, a deny about the subject at any place on the chain blocks the asked permission and whatever implies it. What is left decides.

Two consequences follow. A subject denied a permission at a wide place does not obtain it from an allow at a narrow place inside: a guest who must see one document under a place where they are denied has to lose the deny, not gain an allow. And a group granted something at a wide place is kept out of a narrower place only by an exclusion about that group, since a deny names one subject.

The decision names the statement that decided: the deny that blocked, or the allow or assignment whose permissions were left and satisfied the question. When several statements would decide alike, an engine names one of them, and this document does not say which.

```
decide(subject, groups, permission, target, now):
  carried = empty map from identifier to set of permissions
  for each place K on the chain of target, from the root down to target:
    for each live exclusion e at K about an identifier I in {subject} and groups:
      carried[I] = carried[I] minus removed(value(e))
    for each live allow or assignment s at K about an identifier I in {subject} and groups:
      carried[I] = carried[I] union given(s)
  for each live deny d about subject at a place on the chain:
    if permission == p or permission implies p, for some p in expand(value(d)):
      return denied, d
  if some p in the union of all carried sets satisfies permission:
    return allowed, the statement that gave p
  return denied
```

`given(s)` is the expansion of the permission of an allow, or the `P` of the role of an assignment ([Section 7.1](#71-role-resolution)). `expand` resolves a wildcard against the catalog in force. `removed(X)` is the expansion of `X` together with every permission that implies one of them. `p satisfies permission` when `p` is the permission or implies it.

### 7.1. Role resolution

A role entry is read as follows: an entry containing `:` names a permission, possibly with wildcards, an entry prefixed with `-` is an exclusion of what follows the prefix, and any other entry names a role. What follows `-` is read by the same rule, so `-billing:read` excludes a permission and `-ops` excludes a role: everything the role `ops` resolves to is taken out. The `-` prefix is legal only inside a role definition. The order of entries carries no meaning. An exclusion that removes nothing has no effect. Examples: `support = ["*:read", "-billing:read"]` reads everything except billing, and `manager = ["owner", "-ops"]` holds everything `owner` holds except what `ops` holds. An exclusion of a permission removes it and every permission that implies it, as [Section 5.1](#51-implications) states.

A role that names another role receives what the named role gives, and the named role's exclusions keep applying unless the referencing role names the excluded permission itself, by an exact entry or by a wildcard. Example: `["support", "billing:read"]` reads billing, while `["support", "moderator"]` does not, whatever `moderator` holds. A preset MAY reference presets only. A stored role MAY reference presets and stored roles.

A role `R` resolves to two sets of concrete permissions: `P`, what the role gives, and `E`, what the role still forbids to roles that reference it. Before resolution every wildcard in the role's own entries is expanded against the catalog in force, so the procedure works on plain sets. `own_includes(R)` are the role's own entries that name a permission, `own_excludes(R)` what its own exclusions remove (for a permission, `removed` of it, for a role, that role's `P`), and `refs(R)` the roles it names without the prefix. `P(ref)` and `E(ref)` are the two sets of a referenced role, computed by the same procedure.

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

Grants are carried where the application chooses, for example in a session token or in a server-side session record. The place is the application's choice, the format is normative.

Grants are issued for one or more bases. When no base is named, the base is the root `/`: the grants then cover every place and hold what every live statement about the subject and its groups gives. Issuing for a base writes the entry of the base place, even when nothing is granted there, and folds into it every statement at a place strictly covering the base, so that no key above a base appears in the grants. A statement at the base or under it is written at its own place. A target is covered by the grants when some entry's key lies on the target's chain, because every entry lies at or under a base and every base has an entry, this holds exactly when some base covers the target. Several bases MAY be issued into one set of grants, and an engine MUST accept several sets of grants for one read, treating a target as covered when any set covers it.

Issuing takes the subject and its groups, as the application supplies them at that moment ([Section 7](#7-decision)). Grants hold what the statements about all of them give, per place, without recording which identifier gave what. When the application's notion of who belongs to a group changes, grants already issued keep the old answer until they are reissued.

Grants carry no redundant information. A grant holds only what the statements sitting at its own place give: the permissions allowed there, the permissions denied there, and the permissions that exclusions there take out of what wider places gave. A permission that comes from a wider place is written once, in the grant of that place, and never repeated in the grants below it.

A wildcard is carried as it was written, not expanded: the catalog fingerprint in the version of the grants pins its meaning, and a changed catalog forces a reissue. An assignment of a preset is carried as the name of the preset, which an engine resolves from the presets it already has. An assignment of a stored role is carried as the permissions that role resolves to when the grants are issued, so that reading grants never requires a store.

A read of grants has three outcomes: **allowed**, **denied**, or **not covered**. A target that is not covered yields not covered and nothing else, what follows is the application's decision and outside this document. A covered target is read by the walk of [Section 7](#7-decision) over the entries of its chain, from the root down: a permission given by an entry counts unless an entry below it on the chain, at or above the target, lists that permission as taken out, and a permission denied by any entry blocks. The target is allowed when some permission left is the asked one or implies it, and denied otherwise. This is the decision rule of [Section 7](#7-decision) applied to grants, so for every covered target grants and statements agree by construction. A question against the statements never yields not covered, since the statements cover every place.

The canonical form of grants is an object with two fields defined by this document, `g` and `v`. Any other field of the object belongs to the application. An engine MUST ignore fields it does not define.

`v` is the version of the grants. `g` holds the entries, one per place, keyed by the canonical key of that place. An engine MUST NOT accept a key inside `g` that is not a canonical place key.

An entry has up to four fields, each a list of permissions or of names:

- `a`: the permissions allowed at that place, written as in the statements, wildcards included.
- `d`: the permissions denied there, written as in the statements.
- `r`: the names of the presets assigned there.
- `x`: the permissions taken out, at and under this place, of what the entries above give.

`x` is how an exclusion is carried. At issuing, an engine lists under `x` every permission that an exclusion at this place takes out and that no other statement at a wider place still gives. The permissions are written in full, never as wildcards or role names, because the exclusion was already applied when the entry was written. `x` never lists what a statement at this place or under it gives.

Example. Every member of the platform may read profiles. The staff of one organisation write that organisation's reports, its editors publish them, and a report in the archive is closed: it can be read and published, not created or changed. The subject belongs to three groups: `members`, assigned `member = ["profile:read"]` at the root, `acme-writers`, assigned `writer = ["report:read", "report:write"]` at the organisation, and `acme-editors`, assigned `editor = ["report:publish"]` there. The subject is also allowed `report:export` at the organisation by a statement about the subject alone, and denied `report:delete` there. The group `acme-writers` is excluded from `report:write` under the archive. Issued for the whole tree:

```json
{
  "v": "<version>",
  "g": {
    "/": { "r": ["member"] },
    "/org/acme": { "a": ["report:export"], "d": ["report:delete"], "r": ["editor", "writer"] },
    "/org/acme/archive/2024": { "x": ["report:write"] }
  }
}
```

Under the archive, `report:write` is taken out of what `writer` gave at the organisation, so `x` lists it, and nothing else gives it. `report:read` stays, `writer` names it on its own. `editor` and `report:export` are not listed: the exclusion is about `acme-writers`, and the subject holds those through `acme-editors` and through its own statement. Nothing in the organisation reaches another organisation, since every statement about the organisation's groups sits at `/org/acme`.

The organisation's managers are not held back by the archive. The group `acme-managers` is assigned `manager = ["writer", "editor", "report:delete"]` at the organisation. A second subject, a member of `members` and `acme-managers` only, is issued:

```json
{
  "v": "<version>",
  "g": {
    "/": { "r": ["member"] },
    "/org/acme": { "r": ["manager"] }
  }
}
```

There is no entry for the archive at all: the exclusion is about `acme-writers`, and this subject is not in that group, so nothing is taken out and `manager` writes and deletes under the archive as anywhere else in the organisation. A subject who is in both `acme-writers` and `acme-managers` has `"r": ["manager", "writer"]` at the organisation and no `x` either, because `manager` still gives `report:write` under the archive, so there is nothing to list.

Reading needs the entries at the keys of the target's chain and nothing else, together with whether any of those keys exists. A store MAY keep grants in any layout, as one document, as one row per place key with `a`, `d`, `r` and `x` as columns, or split further, provided a read is handed canonical entries for the keys asked. A store MAY also answer the read itself by the same rule, in which case it MUST implement the rule of this section in full, wildcards and preset names included, and its answer MUST equal what an engine would give for the same entries.

## 9. Sources of answers

TBD. Content already settled for this section:

What the model requires of a store, and nothing more: a store MUST look up the statements of a subject at a place by exact key, for every key of a chain; it MUST keep a statement at the place the engine gave; and whatever form it keeps permissions, places and statements in, what it hands back MUST be the canonical form, as [Section 4](#4-invariants) requires. The lifecycle of statements whose place no longer exists in the application is the application's business: the engine never asks whether a place exists, so such a statement is garbage, not an error. Listing the places under a given one is useful to administration interfaces and MAY be offered, the engine never requires it.

## 10. Authority

TBD. Content already settled for this section:

A change to the statements is one of: placing a statement, removing a statement, or editing a stored role. Every change has an **author**, the subject who asks for it, with its groups. An engine MUST refuse a change that breaks any rule of this section, and an application MUST NOT apply a change the engine refused. The rules exist so that nobody hands out more than they hold, nobody is locked out by a change, and the first statement can exist.

**Manage where you change.** Only a manager of a place changes the statements at that place. Whether the author is a manager is an ordinary question, so a group may make its members managers ([Section 7](#7-decision)).

**Hand out only what you hold.** Placing an allow of a permission at a place requires the author to hold that permission at that place. Placing an assignment requires the author to hold every permission the role resolves to, there. Placing a deny or an exclusion of a permission requires the author to hold that permission there too: one blocks or takes out only what one has. Holding is decided by the ordinary question, so a permission held through an implication or a wildcard counts.

**Never about yourself.** An author never places or removes a statement whose subject is the author's own identifier. The one exception is genesis. A statement about a group the author belongs to is not about the author: an allow to the group gives the author nothing the author did not hold, and a deny about a group blocks nobody ([Section 7](#7-decision)).

**Removal needs management only.** Removing a statement at a place requires management of that place and nothing else. It does not matter who placed the statement, and an engine keeps no record of that for this purpose. A manager may therefore lift a deny or an exclusion that a wider manager placed inside the manager's own place, except one about the manager themselves. A restriction that must stay in force is placed wider than the places its target manages, where the target cannot reach it. The price is that it then applies to everything under that wider place. This is the trade the model makes: a place belongs to its managers, and whoever wants a decision to hold against them takes it at a level above them.

**Restrictions stay within the author's width.** The **width** of an author is the widest place where the author is a manager. A deny or an exclusion reaches other statements: the ones it blocks or takes from. It MAY reach only statements placed at the author's width or under it, and an engine MUST refuse a deny or an exclusion that would reach a statement placed wider. Without this rule a manager of one unit could, inside the unit, block or take out what the organisation's managers granted themselves at the organisation.

**Genesis.** While the root has no manager, anyone MAY place one permanent allow of `*` at the root about one subject. From then on every change follows the rules above. Who triggers genesis is the application's decision.

**The root keeps a permanent manager.** An engine MUST refuse a change after which the root would have no permanent manager. Only statements about subjects count, never statements about groups. Expiry cannot remove the last permanent manager, since a permanent statement does not expire.

## 11. Errors

TBD.

## 12. Limitations

TBD. What the model does not do, with what an application does instead.

**The tree has a root manager.** Someone must make the first change, and an author hands out only what they hold ([Section 10](#10-authority)). So the first manager holds everything at the root, and the root keeps at least one such permanent manager so that every statement stays removable. The model offers no tree without such a subject. The subject is the application's choice and need not be a person: an application that must keep humans away from that power gives it to an identifier nobody signs in as, used only by its own deployment and migration code, and gives people narrower permissions at narrower places from there. An actor who gains write access to the statements store is outside what the model or an engine can address.

## 13. Security considerations

TBD. Content already settled for this section:

The model does not restrict which subjects a manager may place statements about. A manager of a place may place an allow for any subject there, bounded by what the manager holds, and a deny for any subject, bounded by the rules on restrictions. In practice an application often wants a narrower circle, for example only the members of a team or the users of a tenant. That notion of membership is the application's, not the model's: the model knows no grouping of subjects other than the statements themselves. Applications SHOULD therefore constrain, before calling the engine, which subjects a manager may place statements about, and SHOULD treat the resulting refusal as their own, not as a decision of the model.

A deny restricts an identity, not content. A subject denied a permission still obtains whatever the application serves without identification, by asking from another browser, another device or another network. An application that needs content kept from someone MUST NOT serve that content to requests that do not identify themselves.

## 14. References

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
