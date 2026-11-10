# UnAuthZ: A Model for Place-Scoped Authorization with Guaranteed Recoverability

Status: working draft, not yet versioned. Author: Sandro Circi. Licensed under the MIT licence.

## Abstract

UnAuthZ is a model that grounds authorization implementations of any size, from a flat set of roles in one application to multi-tenant platforms that share resources with guests. It defines how stored statements about subjects answer "may this subject do this, here, now", how the answers are carried as grants and read away from the statements without losing exactness over time, and how changes to the statements are governed so that nobody hands out more than they hold and nobody is ever locked out. It addresses three parties, an engine that computes, a store that keeps, and the application that decides, and says what each must do and nothing of how.

## 1. Introduction

This document specifies the UnAuthZ model. It defines the statements an application keeps about its subjects ([Section 3](#3-terminology)), the catalog of permissions they draw from ([Section 5](#5-catalog)), the places they apply to ([Section 6](#6-place)), how they answer a question ([Section 7](#7-decision)), how the answers are carried as grants and read ([Section 8](#8-grants)), what a store must be able to answer ([Section 9](#9-the-store)), and who may change what ([Section 10](#10-authority)). [Section 4](#4-invariants) lists what the model guarantees. [Section 11](#11-errors) names the refusals. [Section 12](#12-limitations) says what the model does not do, and [Section 13](#13-security-considerations) what an application must do for the guarantees to hold. [Appendix A](#appendix-a-scenarios) gives scenarios with the answers the model requires.

The model does not define how statements are laid out in storage, how the parties communicate, how grants are transported, or any programming interface. Those belong to the application and to the store it chooses.

Three design choices run through the whole text. Nothing is matched by pattern: a place is addressed by one key compared byte by byte, and a permission by one spelling. Time only ever removes: a statement may end, nothing starts later, so what grants carry is exact from the moment they are issued until someone writes. And a read looks only for what it asks: which carried values can bear on a question follows from the catalog alone, so an engine never needs to parse what does not relate to it.

## 2. Conventions and notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/info/bcp14) [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

Place keys, permissions and role entries are given in ABNF [RFC5234] in [Appendix C](#appendix-c-abnf). The text of grants is JSON [RFC8259] under the rules of [Section 8.4](#84-canonical-text). Procedures are given in the pseudocode notation of [Appendix B](#appendix-b-pseudocode-notation). Examples are JSON or plain prose, they are illustrative and never normative.

Every time in this document, the end of a statement, the time grants are issued, the time of a question, is an integer count of seconds since 1970-01-01T00:00:00Z, ignoring leap seconds, the `NumericDate` of [RFC7519] without fractions. Two times compare as integers.

## 3. Terminology

This document addresses three parties. An **engine** is software that computes according to this document: it resolves roles, answers questions, issues and reads grants, and checks who may change statements. An engine keeps no statements and performs no input or output. A **store** is software that keeps statements and stored roles and applies changes to them. The application provides it, and [Section 9](#9-the-store) states what the model requires of it. The **application** is the software using an engine and a store: it defines the catalog and the structure, supplies who belongs to which group, chooses where grants are carried, and decides who performs genesis. Everything this document leaves to the application is outside the model.

A **permission** is one action on one kind of resource, written `resource:action`, for example `event:manage`. A permission says what, it never says where. The reserved token `*` is a **wildcard**: in place of the resource, the action or both, it stands for every value the catalog has there. [Section 5](#5-catalog) defines how wildcards resolve and where they are legal.

A **catalog** is the closed list of permissions an application recognises, together with its **implications**: a permission MAY imply others (`event:manage` implies `event:read`), meaning that it includes them. Holding the implying permission satisfies the implied one, a deny of the implied one reaches every permission that implies it ([Section 5.1](#51-implications)). A catalog also declares the application's presets and MAY designate the permission that makes a manager ([Section 5](#5-catalog)). Nothing in a catalog denies by itself.

A **place** is where a statement applies: a position in a path that starts at the single, unnamed **root** and continues through typed **segments**. A segment pairs a **level**, a kind of place the application declared such as `org` or `unit`, with a value the application assigns to name which org, which unit, and that the model compares only for equality. The **structure** is the application's declaration of its levels and of which level may sit under which. The **key** is the string form of a place, for example `/org=org-1/unit=u7`, the root's key is `/`. One place **covers** another when a statement placed at the first applies at the second, and is **wider** than it when it covers it and is not the same place. The **chain** of a place is the ordered list of the places covering it, from the place itself up to the root. [Section 6](#6-place) defines the structure, the key syntax and how coverage is computed. An application whose things need no separation has only the root and writes no place.

A **subject** is whom a statement is about: an identifier the application chooses. For a single user, application or machine it has the meaning of the `sub` claim in JSON Web Token (JWT) [RFC7519]. The application may also choose an identifier for a **group** of them, such as the members of an organisation or a team. Which subjects belong to a group is a fact the application keeps and supplies, never one the model derives. A statement about a group applies to every subject the application says belongs to it ([Section 7](#7-decision)). The subject and its groups together are the subject's **identifiers**.

A **statement** is one stored assertion about one subject at one place. Every statement has the same shape, `{ kind, subject, value, place?, expiresAt? }`, and `kind` names what it asserts:

- `allow`: makes the subject hold the permission in `value` at the place.
- `assign`: makes the subject hold the role named in `value` at the place.
- `deny`: blocks the subject from the permission in `value` at the place and under it, whatever gives it. Nothing placed lower undoes a deny.
- `exclude`: takes the permission in `value` out of what the subject holds at the place and under it. About a group, it takes out only what that group gave. About the subject itself, it takes out the permission whichever identifier's statement gave it. A statement placed lower gives the permission back there ([Section 7](#7-decision)).

`value` is a permission, with wildcards allowed, for `allow`, `deny` and `exclude`, and a role name for `assign`. `place` MAY be absent: an absent place is the root, so an application without places writes none. `expiresAt`, when present, is the time at which the statement ends.

A statement is **live** at a given time when it has no `expiresAt` or `expiresAt` is later than that time. A statement with no `expiresAt` is **permanent**. Nothing in the model starts at a later time: time only ever ends statements.

A **role** is a named list of **entries**, defined once and independent of any place. An entry names a permission, names another role, or, prefixed with `-`, is an **exclusion** that removes what it names from what the other entries give. The same role can be assigned at many places. A role declared in the catalog is a **preset**. A role defined in data is a **stored role**, and it has a **home**, the place where it is defined ([Section 10](#10-authority)). [Section 7.1](#71-role-resolution) defines how a role resolves to permissions.

A **question** is one or more permissions at one **target** place, asked for a subject together with its identifiers, its own and those of the groups it belongs to, at one **time**: "may Alice, a member of `acme-team`, `event:manage` at `/org=org-1`, now?". A question naming several permissions also says whether **all** of them or **any** of them must be satisfied, and MAY ask for every answer. A statement **relates to** a question when it can change its answer. A **decision** is the answer to a question together with its reason: allowed or not, and which statement determined it, for the permission that settled the question or for each permission when every answer is asked for ([Section 7](#7-decision)).

A subject's **grants** are what the statements about the subject and about its groups amount to, written in a form that is carried outside the statements and read without them. Grants are issued at one time and hold a copy of every statement that can relate to a question about the subject, each with its end, so that a read at any later time answers as the statements would, until someone writes. Grants are issued for one or more **bases**, the places they speak for. A target under no base is **not covered**, and a read says so instead of answering. Several grants of one subject read together are **sets**. [Section 8](#8-grants) defines what grants hold, how they are issued and read, and their one written form.

A **manager** of a place is a subject who may change the statements there and may define and edit the stored roles whose home is that place. A subject is a manager of a place by holding, at that place or at a wider one, the permission the catalog designates for it ([Section 5](#5-catalog)). Whether a subject is a manager is always asked of the statements, never of grants ([Section 10](#10-authority)). A permanent statement at the root that gives the manager permission is a **permanent management**, and a subject with such a statement about any of its identifiers is a **permanent manager**. The engine guarantees that such a statement exists, never that an actor stands behind its identifier: that is the application's, as for every identifier.

**Genesis** is the first permanent allow of `*` placed at the root while it has no manager yet. It is the only change to the statements performed by someone who is not a manager, and it is possible only while the root has no manager.

The **author** of a change is the subject who asks for it, with its groups. The **width** of an author, for a change, is the widest place on the chain of the change where the author is a manager. [Section 10](#10-authority) defines the rules that use them.

## 4. Invariants

What the model guarantees, in one place. Each row is a consequence of the sections named with it, which hold the rules and the procedures and cite a row by its identifier where they state it. Rows about a decision start with D, rows about authority with A, rows about what the authority rules guarantee with G.

Canonical forms. Permissions, place keys, times and grants each have exactly one text form, defined in this document. That form is the only one an engine reads or writes. Any other representation that a store, an application or a carrier uses, a column layout, a numeric id, a compressed token, MUST round-trip to the canonical form without loss, so that two things are equal exactly when their canonical forms are equal. This is what lets grants fit a size-constrained carrier such as a cookie-borne token without the model knowing about carriers at all, and what lets engines written in different languages read each other's grants ([Section 6](#6-place), [Section 8](#8-grants)).

What a decision guarantees ([Section 7](#7-decision), [Section 5.1](#51-implications)):

| Id | Guarantee |
| --- | --- |
| D1 | Nothing stated means denied. |
| D2 | A live deny about the subject or about one of its groups, of the asked permission, at any place covering the target, decides against it. Nothing placed lower undoes it. |
| D3 | A deny is exact on what it names and complete on what includes it: denying `event:read` also denies every permission that implies `event:read`, denying `event:manage` leaves `event:read` untouched. |
| D4 | An allow and an assignment only add. An exclusion about a group takes out only what that group gave, so belonging to one more group takes something away only through a deny on that group. An exclusion about the subject itself takes out whatever gave the permission, at its place and under it, and what is given lower stands. |
| D5 | Statements at places not covering the target, and statements that do not relate to the permissions asked, never influence the answer. |
| D6 | The same statements, the same question and the same time give the same answer. A question has one time, fixed when it is asked, however many permissions it names. |
| D7 | The depth of a place never ranks statements. Allows add up along the chain, a deny blocks from any covering place, an exclusion reaches its own place and what lies under it. |
| D8 | Grants issued at a time answer, for every target they cover and at every later time, exactly as the statements live at issue would answer at that time. A target outside every base is reported as not covered, never as denied. |
| D9 | A deny about a group never reaches a permanent manager of the root, so whoever holds a permanent management can always act. |

What authority over a change requires ([Section 10](#10-authority)):

| Id | Rule |
| --- | --- |
| A1 | Manage where you change: only a manager of a place changes the statements at that place and defines or edits the stored roles whose home it is, and whether the author is a manager is asked of the statements. |
| A2 | Hand out only what you hold: an allow or an assignment requires the author to hold what it gives at that place and to be free of a deny of it under that place, a deny or an exclusion requires the author to hold the permission it names there, a stored-role edit requires the author to hold at the home what the role resolves to after it. A preset the catalog marks as assignable by a permission is assigned by whoever holds that permission there. |
| A3 | Never for yourself: an author never places a statement about the author's own identifier, and never removes a deny or an exclusion about it. An author MAY remove an allow or an assignment about itself. Genesis is the one exception to placing. |
| A4 | Remove only what you could give: removing a statement requires management of its place and holding what the statement gives or names, as placing it would. |
| A5 | Restrictions stay within the author's width: a deny or an exclusion reaches only statements placed at the author's width or under it. |
| A6 | Genesis: the first permanent allow of `*` at the root, about one subject, while the root has no manager. The only change made by someone who is not a manager, possible only while the root has no manager. |
| A7 | A stored role has a home: assignable at the home or under it, referencing roles whose home is the same or wider, named uniquely along every chain. |
| A8 | The root never loses its last permanent management through a change, whatever identifier it is about, and no deny or exclusion at the root may silence the last one. |
| A9 | Never a deny on your own group: an author never places a deny about a group the author belongs to. |

What those rules guarantee together ([Section 10](#10-authority)):

| Id | Guarantee |
| --- | --- |
| G1 | No change places a permission the author lacks at the place of the change or is denied under it, a stored-role edit included, unless the catalog names the author's permission as the one that assigns that preset. |
| G2 | The only statement anyone places about themselves is genesis. |
| G3 | No deny or exclusion, at the moment it is placed, reaches a statement placed wider than its author's width. A later move of places may change what it reaches. |
| G4 | Once any statement exists, the root holds at least one permanent management, expiry never removes the last one, and no deny on a group reaches whoever holds it. |
| G5 | Every live statement has someone who may remove it: the root's permanent managers hold everything, so no hard lock is constructible. |

## 5. Catalog

The catalog is the vocabulary an engine holds without a store. It declares the permissions the application recognises, the implications between them, the presets, and, when the application wants managers, the permission that makes one. A preset MAY also name the permission whose holders may assign it without holding what it gives ([Section 10](#10-authority)). It is defined in code, next to the structure, and an engine reads it as it was given. Nothing in a catalog is asked of a store.

A resource, an action, a role name and a level of the structure ([Section 6](#6-place)) are each one **token**: a lowercase ASCII letter followed by at most thirty-one lowercase letters, digits, `-` or `_`, as [Appendix C](#appendix-c-abnf) gives it. A permission is a resource and an action joined by `:`. This spelling is the canonical form of [Section 4](#4-invariants), compared byte by byte, and there is no other: `Report:read` is not a permission in another form, it is refused. An application whose vocabulary is spelled otherwise maps it onto tokens where it defines the catalog.

A permission not in the catalog is **unknown**. An engine MUST refuse an unknown permission in the catalog itself, in a statement being placed, in a stored role being defined or edited, and in a question. A statement or a stored role read from a store that names an unknown permission, because the catalog changed after it was written, is **inert**: an allow or an exclusion of it gives or removes nothing, a deny of it blocks nothing, and the rest of the statement or role applies as written. Grants issued before the change are reissued once their catalog fingerprint no longer matches ([Section 8](#8-grants)). Whether such a statement is rewritten or removed is the application's.

A catalog MAY designate one of its permissions as the one that makes its holder a manager. It is an ordinary permission, named as the application likes: this document reserves no permission name. The designated permission is concrete, never a wildcard. A catalog is valid without it, since answering questions and issuing grants do not need it. An engine MUST refuse every change to the statements when the catalog designates none.

The wildcard `*` MAY stand for the resource (`*:read`), for the action (`event:*`) or for both. The wildcard for every permission is written `*`. `*:*` is not a spelling of it, and an engine MUST refuse it. A wildcard resolves, at the time of the check, to every permission the catalog declares that matches it: `*:read` is every declared permission whose action is `read`, not every resource crossed with `read`. A catalog that grows is therefore covered without a new write. Wildcards are legal in statements and in role entries, never in a question, in an implication or in the manager designation. No other pattern is recognised.

An engine MUST refuse a catalog that declares the same permission twice, a name that is not a token, an implication whose permissions are not both concrete and declared, a cycle of implications, since two permissions that imply each other are one permission, a manager designation that is not a concrete declared permission, or a preset that references a stored role or breaks a rule of [Section 7.1](#71-role-resolution). A refused catalog defines nothing: an engine has a catalog or has none.

An engine derives from the catalog a **fingerprint**: a value that is equal for two catalogs that declare the same permissions, implications, presets and designations, and different otherwise. Grants carry it ([Section 8](#8-grants)). This document does not fix how it is computed. Engines written in several languages that must read each other's grants fix one computation between them, for example a hash over a canonical serialisation of the catalog, and the application is advised to do so from the start.

### 5.1. Implications

An implication is declared in the catalog, from one permission to another: `report:write` implies `report:read`, since writing a report means reading it first. It means that the first permission includes the second: whoever holds `report:write` also satisfies a question about `report:read`. Implications are transitive, a permission may imply several others and be implied by several others, and both permissions of an implication MUST exist in the catalog.

Because the implying permission includes the implied one, a deny of a permission also denies every permission that implies it, directly or through a chain, since exercising any of those would exercise the denied one. It never denies what the denied permission itself implies: denying `report:write` leaves `report:read` as it was (D3). An exclusion in a role removes the permissions it names and every permission that implies them, for the same reason: the role `["*", "-report:read"]` yields neither `report:read` nor `report:write`. So a deny and an exclusion both reach what includes the named permission, and neither touches what it implies. They differ in kind: a deny blocks the action whatever gives it and nothing lower undoes it, an exclusion only withholds what was given, and a narrower allow gives it back.

Example. Catalog: `report:list`, `report:read`, `report:write`, with `report:write` implying `report:read` and `report:read` implying `report:list`. One role, `analyst = ["report:write"]`, for staff who write their own reports, resolved as [Section 7.1](#71-role-resolution) describes. Alice and Bob are both assigned `analyst` at `/org=acme`, Bob also holds a deny of `report:read` there.

| Question at `/org=acme/report=q3` | Alice | Bob |
| --- | --- | --- |
| `report:write` | **allowed**: `analyst` gives it | **denied**: writing would read, and the deny reaches down to it |
| `report:read` | **allowed**: `report:write` implies it | **denied**: the deny names it |
| `report:list` | **allowed**: through the chain | **allowed**: listing does not read, so the deny does not reach up to it |

## 6. Place

A place says where a statement applies. Places form one tree. At the top is the root, which has no name and whose key is `/`. Under it, every place is named by a path of segments, and each segment pairs a level with a value: the level says what kind of place it is (`org`, `unit`), the value says which one (`acme`, `u7`). A statement at a place applies there and everywhere under it.

The application declares the **structure**: the level names, and which level may sit under the root and under which other level. A level MAY have several child levels, MAY sit under several parents, and MAY nest under itself, so a tree may be as deep as the application wants unless its structure says otherwise. The structure is the application's: an engine checks a key against the grammar of [Appendix C](#appendix-c-abnf), never against the structure, and knows nothing about which resources or permissions belong at a level. Whether a given place exists, whether `acme` is a real organisation, is likewise the application's knowledge: it answers that before it asks the engine. Places under the same parent have no order among themselves. One thing has one place at a time: a level that sits under several parents holds different things under each, never one thing with two keys, since a deny at one key would be bypassed at the other.

The **key** is the text of a place, and the only form an engine reads or writes. The root is `/`. Every other key writes its segments from the root down, each as `/`, the level, `=`, the value: `/org=acme/unit=u7`. A `/` starts every segment and appears nowhere else, so a key has as many segments as it has `/` characters. A level never contains `=`, so a segment splits at its first `=`, and a value MAY contain `=`, `:` or any other character that identifiers in the wild use: `/account=did:plc:abc`. [Appendix C](#appendix-c-abnf) gives the grammar.

A level is one token ([Section 5](#5-catalog)). A value is a non-empty sequence of Unicode scalar values, written in UTF-8 [RFC3629] and then percent-encoded as in [RFC3986], in uppercase hexadecimal, for every octet that [Appendix C](#appendix-c-abnf) does not allow literally. An octet that is allowed literally MUST be written literally. One place therefore has exactly one spelling, made of ASCII characters only. One value is reserved and MUST NOT be used: `*`, because it would read as a wildcard. No segment can equal `.` or `..`, since every segment holds a `=`, so a URI parser leaves a key as it is [RFC3986].

A key is either canonical or refused. An engine MUST check that a key is canonical before computing anything from it, and MUST refuse one that is not. It MUST NOT repair a key into canonical form. An application MUST NOT build a key by joining text that was not encoded as a value. It parses a key, or asks an engine to build a key under another.

A value is matched by equality only. There is no pattern or prefix matching on values, because two patterns could cover one target without covering each other, and the places covering a target would no longer form a single line. An application that wants one place to cover a family of values declares the family as a level: `/family=shop/app=preview`, so that a statement at `/family=shop` covers every shop application.

Because no value contains `/`, the keys of the places under a place `K` are exactly the keys that begin with `K/`, except for the root, whose key already ends in `/`: the places under the root are every key other than `/` itself. A store that keeps keys as text and sorts them byte by byte finds them in one run: they all sort at or after `K/` and before `K0`, where `0` is simply the character that follows `/` in ASCII, so `K0` is the first key that begins with `K` and something other than `/`. `K` itself sorts before that run, and a sibling such as `/org=acme-x` MAY sort between `/org=acme` and the keys under it, so the run is the places under `K`, not `K` together with them. A store MAY keep a place in any form it likes, provided it yields the identical key back.

Example. The structure declares `org` under the root, and `unit` and `project` under `org`. `/org=acme/unit=u7` and `/org=acme/project=p3` both sit under `/org=acme`, and the level in each segment tells a unit from a project even when their values collide.

### 6.1. Coverage

A place covers itself and every place under it. The places covering a target are its **chain**, from the target up to the root, and they are totally ordered: each covers the next. That order is what "wider than" means wherever the model uses it. Coverage is the only ordering the model knows.

The procedure takes two keys, `S` where a statement sits and the target `T` of a question, and answers whether `S` covers `T`.

```
covers(S, T):
  if S == "/":                 return true
  if T == S:                   return true
  if T starts with S + "/":    return true
  return false
```

The chain of a key is computed from the key alone:

```
chain(T):
  result = [T]
  while T != "/":
    T = T with everything from its last "/" removed
    if T == "": T = "/"
    append T to result
  return result
```

In the example, the chain of `/org=acme/unit=u7` is itself, `/org=acme` and `/`. `/org=globex` does not cover it, because the segments differ, and `/org=acme/unit=u7` does not cover `/org=acme`, because it is longer.

## 7. Decision

A question is asked for one subject, with the subject's identifiers: its own, and the identifier of every group it belongs to, as the application's source of memberships knows them at that moment. That source is a session, a directory, or the store itself, which can look the groups up in the same read as the statements ([Section 9](#9-the-store)).

A statement applies to the question when its subject is one of those identifiers. That is all the engine does with them: it compares identifiers for equality and knows nothing about who is in which group.

The list of identifiers must be whole. A group left out is a group whose statements do not count, and for a deny that is a block silently missed ([Section 13](#13-security-considerations)). Nothing else about the groups is needed, not their names, not their members, not their number.

The identifiers are needed wherever the statements are read: for a question asked of them, for issuing grants, and for a change. A read of grants needs none, since the grants already hold what every identifier gave ([Section 8](#8-grants)).

A question is answered from the live statements at the places covering the target, and only from those that **relate to** the permission asked. A deny relates to it when it names the asked permission or a permission the asked one implies ([Section 5.1](#51-implications)). An allow relates to it when it names the asked permission or one that implies it, an assignment when its role resolves to one ([Section 7.1](#71-role-resolution)), an exclusion when it takes one out. No other statement can change the answer (D5), and an engine MUST NOT need any other to answer. Which permissions these are follows from the catalog alone, so it is known before any statement is read. Only the assignment of a stored role needs that role's definition to tell.

A question has one time, fixed when it is asked. An engine MUST decide every step of the question against that one time (D6).

First, the denies. If a live deny about the subject or about one of its groups relates to the question, the answer is denied, whatever is given, and nothing more needs to be read (D2, D3). A deny MAY name a wildcard: it then blocks every permission the wildcard expands to, so a deny of `*` at a place blocks the subject from everything at and under that place. One exception protects recovery (D9): a deny about a group does not apply to a subject who is a permanent manager of the root, which the engine sees in the same statements.

Second, what is given (D4). Each allow and each assignment about one of the subject's identifiers gives that identifier a set of permissions: what the permission of an allow expands to, or what the role of an assignment resolves to ([Section 7.1](#71-role-resolution)). An exclusion about a group takes out of what that group was given, at the exclusion's place and under it, the permission it names and every permission that implies it. An exclusion about the subject itself takes the same out of what every identifier was given, at its place and under it. An exclusion wins at its own place: what the same place gives is taken out too, exactly as `-` wins inside a role. What a narrower place gives stands, whoever it is about. The answer is allowed when some permission left is the asked one or implies it, and denied when none is (D1).

The depth of a place never ranks statements (D7), it only orders the walk. Read the chain from the root down to the target, carrying for each identifier what has been given so far of the permissions that satisfy the question. At each place, first add what the allows and assignments there give, then take out what the exclusions there remove. What is left at the target decides.

Two consequences follow. A subject denied a permission at a wide place does not obtain it from an allow at a narrow place inside: a guest who must see one document under a place where they are denied has to lose the deny, not gain an allow. And an exclusion is the tool for "everything except one": excluded at the place that holds twenty archives and allowed at one of them, a subject writes in that one archive and in no other, and in no archive created later.

The decision names the statement that decided: the deny that blocked, or the allow or assignment whose permissions were left and satisfied the question. When several statements would decide alike, an engine names one of them, and this document does not say which.

```
decide(subject, groups, permission, target, now):
  blocking = permission and every permission it implies
  wanted   = permission and every permission that implies it
  exempt   = a live permanent statement at the root about subject or a group in groups gives the manager permission
  for each live deny d at a place on the chain of target, about subject or about a group in groups:
    if d is about a group and exempt: continue
    if some p in expand(value(d)) is in blocking:
      return denied, d
  carried = empty map from identifier to set of permissions
  for each place K on the chain of target, from the root down to target:
    for each live allow or assignment s at K about an identifier I in {subject} and groups:
      carried[I] = carried[I] union (given(s) intersected with wanted)
    for each live exclusion e at K about a group G in groups:
      carried[G] = carried[G] minus removed(value(e))
    for each live exclusion e at K about subject:
      for each identifier I: carried[I] = carried[I] minus removed(value(e))
  if some carried set is not empty:
    return allowed, the statement that gave one of its permissions
  return denied
```

`given(s)` is the expansion of the permission of an allow, or the `P` of the role of an assignment ([Section 7.1](#71-role-resolution)). `expand` resolves a wildcard against the catalog in force. `removed(X)` is the expansion of `X` together with every permission that implies one of them. A permission in `wanted` satisfies the question, a permission in `blocking` is what a deny must name to block it.

A question MAY name several permissions at its one target. It then MUST say whether all of them or any of them must be satisfied: the question says it, never the answer, and there is no default. Each permission is decided as its own question would be, against the one time of the question, from the statements that relate to any of the permissions named. The question is allowed under all when every permission is allowed, and under any when at least one is. A question naming one permission is the same under both and says neither.

By default an engine stops as soon as the question is settled. It looks at the denies first, for every permission named: under all, one permission blocked by a deny settles the question as denied, under any, a blocked permission is set aside. It then looks at what is given, permission by permission in the order asked: under all, the first permission that nothing gives settles the question as denied, under any, the first permission given settles it as allowed. The decision carries the outcome and the answer that settled it, with the permission it is about. When nothing settles the question early, every answer was needed and the decision carries them all.

A question MAY ask for **every answer** instead, for an interface that shows what is missing or for diagnosis. An engine then decides every permission and MUST return one answer per permission, each with its reason. The outcome is the same either way. Whatever answers a decision carries, an engine MUST return them in the order in which their permissions were asked.

```
decide_several(subject, groups, permissions, mode, every, target, now):
  if every:
    answers = decide(subject, groups, p, target, now) for each p in permissions, in the order asked
    return combined(mode, answers), answers
  answers = empty list
  for each p in permissions, in the order asked:
    if a live deny that applies blocks p:
      answer = denied, naming that deny
      if mode is all: return denied, answer
      add answer to answers, and set p aside
  for each p in permissions not set aside, in the order asked:
    answer = decide(subject, groups, p, target, now)
    if mode is all and answer is denied: return denied, answer
    if mode is any and answer is allowed: return allowed, answer
    add answer to answers
  return combined(mode, answers), answers in the order their permissions were asked
```

`combined` is allowed under all when every answer is allowed, under any when some answer is allowed, and denied otherwise.

An engine MUST refuse, as a whole, a question that names no permission, an unknown permission or a wildcard, one that names several permissions without saying all or any, and one that carries no time. A permission named twice counts once, and is answered at each of its positions when every answer is asked for. A question has one target, so the same permissions at several places are several questions. Any other combination, one permission together with either of two others for example, is the application's to compute from every answer.

### 7.1. Role resolution

A role entry is read as follows: an entry containing `:` names a permission, possibly with wildcards, an entry prefixed with `-` is an exclusion of what follows the prefix, and any other entry names a role. What follows `-` is read by the same rule, so `-billing:read` excludes a permission and `-ops` excludes a role: everything the role `ops` resolves to is taken out. The `-` prefix is legal only inside a role definition. The order of entries carries no meaning. An exclusion that removes nothing has no effect. Examples: `support = ["*:read", "-billing:read"]` reads everything except billing, and `manager = ["owner", "-ops"]` holds everything `owner` holds except what `ops` holds. An exclusion of a permission removes it and every permission that implies it, as [Section 5.1](#51-implications) states.

A role that names another role receives what the named role gives, and the named role's exclusions keep applying unless the referencing role names the excluded permission itself, by an exact entry or by a wildcard. Example: `["support", "billing:read"]` reads billing, while `["support", "moderator"]` does not, whatever `moderator` holds. The rule exists so that composing roles never silently gives back what one of them was built to withhold: a withheld permission returns only when the composing role names it. A preset MAY reference presets only. A stored role MAY reference presets and stored roles.

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

Grants are carried where the application chooses, in a signed token, in a server-side session record, in any store of its own. Where they live and how they travel is the application's decision. What they hold, how they are issued, how they are read and their one written form are normative.

### 8.1. What grants hold

Grants are issued for one subject, at one time, from the statements live at that time about the subject's identifiers, its own and those of its groups, as the application's source of memberships knows them. They hold:

1. **The bases**, the places the grants speak for. The root when none is named. A target under no base is not covered.
2. **A copy of every statement that can relate to a question** about the subject: its kind, its value as written, its place, and its end when it has one. A permission is kept as written, wildcards included. A preset is kept by name. A stored role is kept as the permissions it resolved to at issue, written once and referenced from every place where it is assigned.
3. **Bundles.** What a group gave the subject is kept together as a **bundle** when that group also has an exclusion in the grants. Every value of the bundle, and the group's exclusion itself, carries the bundle's number, so that the exclusion closes its own bundle and nothing else. Values outside every bundle are the subject's own or came from groups without exclusions, and an exclusion without a number is the subject's own and reaches everything. Denies carry no number. A bundle number never says which group it was, and the numbers are assigned anew at each issue.
4. **The time they were issued**, so that a read at an earlier time is refused.
5. **The revision of this format and the fingerprint of the catalog** they were written for, so that an engine refuses what it cannot read and says which of the two differs.

Grants hold nothing else about the subject: not the names of its groups, not who placed a statement, not statements that had ended at issue, not statements about other subjects. An application's own fields live beside the grants in its carrier, never inside the canonical text, and an engine reads only the grants.

Grants freeze what the statements held at issue. A statement that ends later ends in the grants too, because its end travels with it: a value whose end has passed does not count, and nothing else changes. A statement placed or removed later is not in the grants: the delay between such a write and the next issue is the application's choice, through where it keeps its session and for how long. An application that accepts no delay asks the statements directly ([Section 7](#7-decision)).

Membership is frozen too. Grants reflect the groups the subject was in when they were issued. Joining or leaving a group afterwards changes nothing until new grants are issued.

### 8.2. Issuing

Issuing takes the subject, its groups, the bases and the time of issue, reads the statements that relate to the subject or its groups and are live at that time, and the definitions of the stored roles those statements assign, and writes the grants. A statement is kept when its place lies on the chain of a base or under a base. A deny about a group is left out when the subject is a permanent manager of the root (D9). Nothing is folded: a statement above a base stays at its own place.

Bundles are numbered in three steps. Take the groups that have at least one exclusion kept in the grants. For each of them, write its bundle, the values given, denied or taken out by statements about that group, as canonical text with the number left blank. Sort those texts by bytes and number them from 1 upwards. Two groups whose bundles are identical share one number: they gave and took out exactly the same, so closing one closes the other without changing any answer. No other group has a bundle.

Two engines issuing from the same statements for the same subject, groups, bases and time MUST produce the same text.

### 8.3. Reading

A read takes grants, one permission, one target and one time, and gives one of three answers: **allowed**, **denied**, or **not covered**. It refuses instead of answering when the grants are malformed, when their format revision or catalog fingerprint is not the engine's own, or when the time of the question is earlier than the time of issue ([Section 11](#11-errors)). A refusal is not an answer, and the model does not say what the application does next.

The read needs no store and no walk. From the catalog alone it knows, for the permission `p`, `blocking(p)`, `wanted(p)` and `down(p)`: the permissions a deny must name, the permissions that satisfy `p`, and the permissions an exclusion must name to take one of those out, that is `wanted(p)` with everything one of them implies. The values it looks up are the spellings that can carry one of those permissions, four for each: for `report:write` they are `report:write`, `report:*`, `*:write` and `*`. It also looks up the presets whose resolution meets `wanted(p)` and the stored roles whose row meets it, and touches no other value.

```
read(grants, p, target, t):
  refuse when grants are malformed, or name another format revision or catalog fingerprint
  refuse when t < issue time of grants
  if no base covers target: return not covered
  for each deny (value v, place P, end e) with v a spelling of blocking(p):
    if live(e, t) and covers(P, target): return denied, that deny
  X = every exclusion (value v, place E, end e, bundle m)
        with v a spelling of down(p), live(e, t) and covers(E, target)
  for each given value (value v, place A, end e, bundle m) that meets wanted(p):
    if not live(e, t) or not covers(A, target): continue
    for each q in given(v) that is in wanted(p):
      if no x in X has covers(A, place of x) and q in removed(value of x)
         and (x has no bundle or bundle of x = m):
        return allowed, that value
  return denied

live(e, t): e is absent, or e > t
```

This read gives the answer of the walk of [Section 7](#7-decision): a given value counts when it is live, its place covers the target, and no live exclusion that applies to it sits at its place or under it on the chain. A deny on a group blocks every member, so denies belong to no bundle. For every covered target the grants and the statements live at issue agree at every time (D8), and the two readings never diverge before someone writes. A question naming several permissions is read as [Section 7](#7-decision) settles all and any, denies first, at one time.

Several sets of one subject MAY be read together, for example a small set for the platform in a cookie and a deep set for a drive kept server side. A target is covered when any set covers it, and it is allowed only when every set covering it allows. Each set alone is exact for the targets it covers, so two sets disagree only when one was issued before a change: requiring every one to allow lets the older set's deny stand, which is the safe side. A set that refuses makes the read refuse. Bases of sets read together SHOULD NOT cover each other, so that no statement is carried twice and reissued twice.

### 8.4. Canonical text

The canonical text of grants is one JSON object [RFC8259] with the members below and no others, serialised with no whitespace, members in the order listed, strings with the escapes RFC 8259 requires and no others, numbers as integers.

- `v`: the revision of this format, the string `"1"` for this document. A later revision of this document raises it only when a read of grants written under the earlier one would differ.
- `c`: the fingerprint of the catalog, a string ([Section 5](#5-catalog)).
- `at`: the time of issue.
- `b`: the bases, a list of canonical keys in byte order, each once. Absent when the only base is the root.
- `p`: the **place table**, a list of canonical keys in byte order, each once, holding every place that some item names except the root. Absent when no item names a place.
- `r`: the **role table**, a list of rows, each row the sorted list of concrete permissions a stored role resolved to, each row once, in byte order of the rows. Absent when no stored role is assigned.
- `g`: the **entries**, an object whose member names are the values carried: a permission or a pattern as written, a preset name, or `#` followed by the index of a row of `r`. Members in byte order.

An entry is an object with up to three members, in this order: `a` for what is given, `d` for what is denied, `x` for what is taken out. `d` and `x` appear only in entries whose name is a permission or a pattern. Each member is a list of **items**, and an item is a list of up to three elements: the index of the place in `p`, or `null` for the root, then the end, or `null` when permanent, then the bundle number. Trailing elements that are `null` or absent are omitted, so `[]` is the root with no end and no bundle, `[3]` is the fourth place of `p`, `[3,1794819600]` adds an end, and `[null,null,2]` is the root in bundle 2. Items of one list are sorted by place index, the root first, then by end, permanent first, then by bundle. Two items of one list with the same place and bundle are one item, with the later end, or no end if either has none. A value whose every item had ended at issue is not written, and an entry with no items is not written.

The examples below are shown with whitespace for reading, the canonical text has none. Zoe is allowed `report:*` and excluded from `report:write` at the organisation:

```json
{
  "v": "1",
  "c": "9f2c…",
  "at": 1794214800,
  "p": ["/org=acme"],
  "g": { "report:*": { "a": [[0]] }, "report:write": { "x": [[0]] } }
}
```

A bundle, in one case. Sue's team is assigned `writer` at the organisation and excluded from `report:write` in the archives. Sue herself is allowed `report:write` at the organisation until Friday. Three values come out of this. The team has an exclusion, so what it gave forms bundle 1, while Sue's own allow is in no bundle:

```
writer         given      at /org=acme                 bundle 1    from the team
report:write   given      at /org=acme, ends Friday    no bundle   from Sue herself
report:write   taken out  at /org=acme/area=archives   bundle 1    the team's exclusion
```

The grants are issued on Monday 2026-11-09 at 09:00 UTC, `1794214800`. Her allow ends on Friday 2026-11-13 at 00:00 UTC, `1794528000`, so it is live on Thursday and ended on Saturday. A read in the archives closes bundle 1 only: `writer` no longer gives `report:write` there. Sue's own allow is in no bundle, so the exclusion does not touch it, and on Thursday she writes. On Saturday her allow has ended: denied. Had the exclusion been placed on Sue herself, it would carry no number and would take the permission out of everything, her own allow included. A group with no exclusion anywhere in the grants has no bundle, and its values look exactly like the subject's own.

The same grants as canonical text:

```json
{
  "v": "1",
  "c": "9f2c…",
  "at": 1794214800,
  "p": ["/org=acme", "/org=acme/area=archives"],
  "g": {
    "report:write": { "a": [[0, 1794528000]], "x": [[1, null, 1]] },
    "writer": { "a": [[0, null, 1]] }
  }
}
```

Elsewhere in the organisation `writer` still gives `report:write` to Sue on Saturday, since the exclusion covers the archives only.

A flat application with no places writes no `p` and items of `[]`. Ed, assigned `viewer` permanently and `editor` until next Monday:

```json
{
  "v": "1",
  "c": "9f2c…",
  "at": 1794214800,
  "g": { "editor": { "a": [[null, 1794819600]] }, "viewer": { "a": [[]] } }
}
```

An application MAY carry grants in any other form, nested, abbreviated or split into rows, as long as it converts to this text and back without loss ([Section 4](#4-invariants)). An engine reads and writes the canonical text only.

### 8.5. When grants are issued again

Grants need no reissue for an expiry: every end travels with its value. They are issued again when the statements about the subject or its groups change by a write, when the subject's groups change, when a stored role they carry is edited, when the catalog changes, or when the application moved or removed places they cover ([Section 10](#10-authority)). A read refused for another catalog is the signal for the catalog case. For the others the application decides, from the delay it accepts and the lifetime it gives its session, and a store MAY record when statements last changed so that the application can compare it with `at` where a read happens anyway.

## 9. The store

A store is whatever keeps the statements and the stored roles and answers for them, over any protocol and in any layout. The model says what it must be able to answer, never how it is built. Whatever it keeps inside, what it hands back MUST be the canonical form of every key, permission, time and statement, as [Section 4](#4-invariants) requires.

A store MUST answer four questions. Given a list of identifiers and a list of place keys: the live statements about any of them at exactly those places. Given a place key: the live statements at exactly that place, about any identifier, which the rules on the root need. Given a place key: the statements at the places under it, live or not, which moves and administration need. Given role names: the stored roles of those names, with the roles they reference. A store MUST keep a statement at the place the engine gave. It MAY record the time at which each statement was placed or removed, so that an application can compare it with the `at` of issued grants ([Section 8](#8-grants)). A store MUST compare keys and subjects byte by byte, for equality and for order, since a collation that folds case or ignores punctuation returns another place's or another subject's statements.

A store SHOULD also answer, in one exchange, everything issuing needs: given a subject with its groups and the bases, the live statements about them on the chain of each base and under each base, with the stored roles those statements name. A store that can combine reads then answers in one round trip. One that cannot answers in several, and the model asks nothing about how many. A store MAY also take, with a question, the values that relate to it and return only the statements holding them, together with every assignment of a stored role, which only its definition can settle. Presets are never asked of a store, they are part of the catalog an engine holds.

A change to the statements is checked against the statements ([Section 10](#10-authority)): a change reads what the author holds, the statements it touches and the statements at the root, then writes. A store that combines those reads serves a change in one read and one write.

The lifecycle of statements whose place no longer exists in the application is the application's business: the engine never asks whether a place exists, so such a statement is garbage, not an error. Listing the places under a given one is useful to administration interfaces and MAY be offered, the engine never requires it.

## 10. Authority

A change is placing a statement, removing one, or defining or editing a stored role. Every change has an **author**, the subject who asks for it, with its identifiers as [Section 7](#7-decision) defines them. An engine MUST refuse a change that breaks any rule of this section, and an application MUST NOT apply a change the engine refused. The rules exist so that nobody hands out more than they hold (G1), nobody writes about themselves but at genesis (G2), no restriction reaches above its author when placed (G3), the root never loses its last permanent manager (G4), and every statement stays removable (G5). [Section 4](#4-invariants) lists them. They bound a change by what its author holds and nothing more. How much of the catalog a manager may use at all, presets included, and which managers may make which changes where, is the application's narrowing on top of them, and this document does not say it.

Everything a rule of this section asks about the author, whether the author manages the place and what the author holds, is asked of the statements at the time of the change, never of the author's grants (A1). Grants decide what a subject may do, the statements decide what a subject may change. A manager removed a minute ago cannot act from grants issued before.

**Manage where you change (A1).** Only a manager of a place changes the statements at that place. Whether the author is a manager is an ordinary question against the statements, so a group may make its members managers ([Section 7](#7-decision)).

**Hand out only what you hold (A2).** Placing an allow of a permission at a place requires the author to hold that permission at that place, and no live deny of that permission that applies to the author, about the author or about one of its groups, at any place under it: what an allow gives reaches everything under its place, and an author banned somewhere inside does not hand out a way around the ban. Placing an assignment requires the same for every permission the role resolves to. An exclusion about the author under the place does not refuse the change, since an exclusion is answerable lower down by design ([Section 7](#7-decision)). Placing a deny or an exclusion of a permission requires the author to hold that permission at the place: one blocks or takes out only what one has. Holding is decided by the ordinary question, so a permission held through an implication or a wildcard counts.

One exception lets the management of people be separated from the use of content. The catalog MAY name, for a preset, a permission whose holders assign that preset without holding what it gives ([Section 5](#5-catalog)). Whoever holds that permission at a place assigns the preset there. Only the holding requirement of this rule is replaced: the holder still manages the place (A1), assigns nothing to themselves (A3) and stays within the other rules. An application that wants a user manager who cannot read what the users read declares it this way.

**Never for yourself (A3).** The author's own identifier is the subject's, never a group's: a statement about a group the author belongs to is not about the author, with one exception below (A9). An author never places a statement whose subject is its own identifier, and never removes a deny or an exclusion about it. The one exception to placing is genesis. An author MAY remove an allow or an assignment about itself: leaving a role is one's own decision, lifting one's own restriction is not. That removal is exempt from A1, A2 and A4, and bound by A8 alone. Leaving a group needs no statement at all, since membership is the application's fact.

**Remove only what you could give (A4).** Removing a statement requires management of its place and holding what the statement gives or names, as placing it would. A manager who could not have placed a statement cannot remove it, so a lower manager never strips a higher one, while the higher one may strip the lower. It does not matter who placed the statement, and an engine keeps no record of that for this purpose. A manager may therefore lift a deny or an exclusion that a wider manager placed inside the manager's own place, if the manager holds the permission it names there. A restriction that must stay in force is placed wider than the places its target manages, where the target cannot reach it. The price is that it then applies to everything under that wider place. A place belongs to its managers, and whoever wants a decision to hold against them takes it at a level above them.

**Restrictions stay within the author's width (A5).** The **width** of an author, for a change, is the widest place on the chain of the change where the author is a manager. A deny or an exclusion reaches other statements: the ones it blocks or takes from, about the same identifier it is about. It MAY reach only statements placed at the author's width or under it, and an engine MUST refuse a deny or an exclusion that would reach a statement placed wider. Without this rule a manager of one unit could, inside the unit, block or take out what the organisation's managers granted themselves at the organisation.

**Genesis (A6).** While the root has no manager, anyone MAY place one permanent allow of `*` at the root about one subject, the author itself included: this is the one time anyone writes about themselves. From then on every change follows the rules above. Who triggers genesis is the application's decision. A stranger's first access afterwards comes in one of two ways. Either the application acts as a subject of its own, say `signup`, that holds only what sign-up may give, so that this section checks the change like any other. Or every member is listed in a members group that holds one assignment, and the application lists the newcomer in it, writing no statement at all.

**Stored roles have a home (A7).** A stored role's home is the place where it was defined, the root for a tree-wide one. It MAY be assigned only at its home or under it, and MAY reference presets and stored roles whose home is its own or a wider place, never a narrower one. Its name MUST NOT be the name of a preset, nor of a stored role whose home lies on the same chain, wider or narrower, so that a name read at any place has one meaning. An engine MUST refuse a definition that breaks any of these.

Defining or editing a stored role is a change at its home, and the two rules above apply to it as to any change: the author is a manager of the home, and holds there every permission the role resolves to after the change, since an edit hands its new permissions to everyone who holds the role, at every place where it or a role referencing it is assigned. Renaming or deleting a stored role that is assigned or referenced changes what those statements mean. Like a move, it is a rewrite the application performs on its store, within the places it manages, deciding itself whether to refuse, to cascade or to rewrite, and it reissues the grants that carried the role, since a stored role is carried as the permissions it resolved to when the grants were issued ([Section 8](#8-grants)).

**A move is not a change of the model.** Moving a thing to another place rewrites the keys of the statements at and under its old place, which the application does on its store, within the places it manages. The rules of this section hold at the moment a statement is placed. A restriction that was within its author's width when placed may reach wider after a move, and the application that moves places accepts that, or checks the moved restrictions again.

**The root keeps a permanent management (A8).** An engine MUST refuse a change after which no permanent statement at the root would give the manager permission, whatever identifier the remaining one is about, a subject or a group. A permanent management counts only while no live deny or exclusion at the root takes the manager permission from its identifier. A deny or an exclusion at the root that would leave none counting is refused, even one with an end, since the lock would hold until that end. Expiry cannot remove the last one, since a permanent statement does not expire. The engine cannot tell a subject from a group and does not need to: it guarantees the statement, and the application keeps an actor behind its identifier. A deny about a group never reaches a permanent manager of the root (D9), so one always remains who can remove any statement (G5).

**Never a deny on your own group (A9).** An author never places a deny about a group the author belongs to. The application supplies the author's groups with the change, as with any question. Without this rule a manager would block themselves with no way back but a wider manager.

## 11. Errors

An engine refuses rather than guesses. Every refusal names one of the reasons below, so that an application can tell them apart in its own logic, and the model does not say how a refusal is carried in a given language or what the application does next. A refusal is never one of the answers allowed, denied or not covered.

- **invalid catalog**: the catalog breaks a rule of [Section 5](#5-catalog). The engine has no catalog.
- **unknown permission**: a permission not in the catalog, in a question, in a statement being placed or in a role being defined. Statements read from a store that name one are inert, never an error ([Section 5](#5-catalog)).
- **malformed**: a key, a permission, a pattern, a role entry, a time or grants that do not match their canonical form, `*:*` and a non-canonical key included.
- **invalid question**: no permission, a wildcard, several permissions with neither all nor any, or no time.
- **invalid role**: a stored role that references an unknown role, a cycle, a home or a name that breaks [Section 10](#10-authority).
- **refused change**: a change that breaks a rule of [Section 10](#10-authority), naming every rule it breaks, A1 to A9.
- **other format**, **other catalog**: grants whose revision or fingerprint is not the engine's own, named apart so that the application knows whether its own code or the engine changed.
- **before issue**: a read of grants at a time earlier than their time of issue.

## 12. Limitations

What the model does not do, with what an application does instead.

**A key is a position, not an identity.** The model knows a thing only by where it sits. When a thing moves, its key and the keys under it change, and the application rewrites the statements there and reissues the grants that covered them ([Section 8](#8-grants), [Section 10](#10-authority)). When a place is deleted and its value used again for another thing, the statements left there apply to the new thing. An application that must tell two things apart over time uses stable identifiers as values and removes the statements of what it deletes.

**Deep trees cost space, and so do many short-lived statements.** A key carries its whole ancestry, and grants write each place once. A subject with many dated shares carries one item per share, and a carrier the size of a cookie holds a few dozen of them, whatever the form. An application with deep trees or many shares carries grants server side, or issues them for a base near the target, and it states the limit of the carrier it chose.

**The tree has a root manager.** Someone must make the first change, and an author hands out only what they hold ([Section 10](#10-authority)). So the first manager holds everything at the root, and the root keeps at least one such permanent manager so that every statement stays removable. The model offers no tree without such an identifier, and it guarantees only the statement: whether a person, a job or a populated group stands behind the identifier is the application's to keep true. The identifier is the application's choice and need not be a person: an application that must keep humans away from that power gives it to an identifier nobody signs in as, used only by its own deployment and migration code, and gives people narrower permissions at narrower places from there. An actor who gains write access to the statements store is outside what the model or an engine can address.

**No restriction on everyone except a few.** A deny on a group blocks every member, and nothing lifts it for some of them. An application that wants exceptions keeps the exempt subjects out of that group.

**No conditions.** A statement's only condition is its end. A restriction that depends on the state of a thing is asked as a different permission for that state, named on the resource, such as `archived-report:write`. An attribute of the request, the network or the time of day is the application's to check before it asks.

**No end on a membership.** A group has members as long as the application lists them. Access that must end at a time is given by a statement with an end, about the subject or about the group.

**No rule for the direct children of a place only.** A statement reaches everything under its place. An application that wants a rule for one level gives those things a place of their own.

**No cap cut against what statements give.** The model adds and blocks, it never intersects. A credential that may do less than its user is the application's, outside the statements.

**Recovery is outside the model.** The model guarantees that someone may always remove any statement. Who that someone is, and how they sign in, is the application's.

## 13. Security considerations

**Supply the whole list of identifiers.** A deny about a group blocks only the subjects whose identifiers include that group. A group left out of a question or a change turns a block into nothing, silently. An application MUST hand the engine the subject's identifiers whole, from the same source of memberships each time, whether that source is a session, a directory or the store.

**Ancestry comes from where the thing is.** An engine trusts the ancestry written in a key. A key built from a request alone, from a route or a parameter, lets a caller claim a position its thing does not have and be answered for that position. An application MUST derive the key from where the thing actually is, or check the claimed key in the action's own read of the thing, and MUST NOT take the ancestry from the request alone.

**One spelling per name.** Two spellings of one accented name are two places, and a deny placed at one is missed at the other. An application MUST bring every name to one form before it becomes a value in a key.

**Clock and unit.** A read lifts an expired deny or exclusion on its own. A clock that runs ahead lifts them early, and a time counted in the wrong unit lifts them at once or never. Every time in the model is an integer count of seconds ([Section 2](#2-conventions-and-notation)), an engine applies no leeway, and an application that wants one applies it on its own clock, knowing that it moves denies and allows alike.

**A deny restricts an identity, not content.** A subject denied a permission still obtains whatever the application serves without identification, by asking from another browser, another device or another network. An application that needs content kept from someone MUST NOT serve that content to requests that do not identify themselves.

**Who may be written about.** The model does not restrict which subjects a manager may place statements about. A manager of a place may place an allow for any subject there, bounded by what the manager holds, and a deny for any subject or group, bounded by the rules on restrictions. In practice an application often wants a narrower circle, for example only the members of a team or the users of a tenant. That notion of membership is the application's, not the model's. Applications SHOULD therefore constrain, before calling the engine, which subjects a manager may place statements about, and SHOULD treat the resulting refusal as their own, not as a decision of the model.

**What grants reveal.** Grants carry the places and permissions a subject holds or is kept out of, and a number that says which values share a group without naming it. Whoever reads the carrier learns that much, including the key of a place the subject is excluded from. An application that must hide the existence of a place from a subject keeps that subject's grants away from the subject, or keeps the restriction in a group deny whose place the subject never sees.

**Keys have no bound in the model.** An engine checks a key against its grammar before computing anything, and an application MAY refuse keys over a length or depth it declares, so that a hostile request cannot hand it a chain of thousands of places.

**Changes are checked live.** Whether an author manages a place and holds what they hand out is asked of the statements at the time of the change ([Section 10](#10-authority)). A change touches the store anyway, so the check costs no extra trip, and a removed manager cannot act from an earlier credential.

## 14. References

- RFC 2119, Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, March 1997. [RFC2119]
- RFC 8174, Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, May 2017. [RFC8174]
- RFC 5234, Crocker, D. and P. Overell, "Augmented BNF for Syntax Specifications: ABNF", STD 68, January 2008. [RFC5234]
- RFC 7519, Jones, M., Bradley, J. and N. Sakimura, "JSON Web Token (JWT)", May 2015. [RFC7519]
- RFC 8259, Bray, T., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, December 2017. [RFC8259]
- RFC 3986, Berners-Lee, T., Fielding, R. and L. Masinter, "Uniform Resource Identifier (URI): Generic Syntax", STD 66, January 2005. [RFC3986]
- RFC 3629, Yergeau, F., "UTF-8, a transformation format of ISO 10646", STD 63, November 2003. [RFC3629]

## Appendix A. Scenarios

Each scenario lists a few statements and the answers the model gives. The answers hold when asked of the statements and when asked of grants issued from them. Unless a scenario says otherwise, nothing changes over time. Names are illustrative.

**A.1. One person and an assistant, no places.** Ed signs in first, and genesis makes him the permanent manager: he holds `*` at the root. He runs an agent, `assistant`, and allows it `post:read` and `post:draft`.

- The assistant reads a post: allowed. Drafts one: allowed. Publishes one: denied, nothing gives it.
- Ed publishes a post: allowed.
- The assistant allows itself `post:publish`: refused, nobody writes about themselves.
- Ed allows the assistant `post:publish`: accepted, he holds it. From then on the assistant publishes.

**A.2. A code forge.** Organisations hold repositories. Teams are groups. The web team is assigned `writer` at one repository, and Lea is assigned `developer` at one project by name. Mel holds `access:manage` at that project, and her grants live in a cookie the application accepts for an hour.

- Lea removes her own `developer` assignment: accepted. Lea removes a deny placed on her: refused. Lea assigns `developer` to herself: refused.
- A manager removes Mel's `access:manage`. Minutes later Mel assigns `maintainer` to her second account: refused, the statements say she no longer manages. In the same minute she reads the project from her cookie: allowed, within the delay the application chose.
- Mia, a moderator holding `access:manage` and `member:kick`, removes the owner's `*`: refused, she does not hold it. The owner removes the moderators' `access:manage`: accepted.

**A.3. A cloud account tree.** The platform's owner manages the root. Every subject of the organisation `acme` is in its members group. Tom administers `acme`, holds `*` there, and is in that group.

- The owner places a deny of `audit-log:delete` on the members group at `acme`. Tom deletes an audit log: denied. A member who joins next month: denied. The owner's own people, outside the group and allowed at the root: allowed.
- Tom places a deny on a group he belongs to: refused. The owner places a deny of `access:manage` on the staff group, which lists everyone but the owner, the deploy job included: the deploy job holds a permanent management, so the deny does not reach it, and the deploy job removes the deny.
- Dan holds `*` at `acme` and is denied `report:read` in its archives. Dan allows Ike `report:read` at `acme`: refused, the allow reaches the archives. With an exclusion in place of the deny: accepted, and a manager of the archives could have given it back anyway.

**A.4. A shared drive.** Folders nest under a drive. The marketing group is assigned `viewer` at the drive. Pat's grants are issued for the drive only. Sue is allowed to read one file for two hours.

- A file added to a folder later: readable by the group, with no statement written.
- Three hours on, Sue reads her file: denied. Everything else she holds: unchanged, and nothing was issued again.
- Pat asks about the platform's billing page: not covered, never denied.
- A folder is limited to people added directly: the application asks `limited-file:read` there, which `viewer` does not include, and only direct allows of it count.
- A unit moves to another drive and its statements are rewritten: a deny placed at the old drive no longer applies under the new one.

**A.5. A chat server.** Channels sit under the server. Gil is assigned `player` at the server.

- A deny of `match:join` is placed on Gil until next Monday after three strikes: Thursday, join: denied. Next Tuesday: allowed, with nothing issued again.
- An exclusion of `chat:send` on Gil at the server and an allow at the help room: lobby, denied. Help room, allowed.
- A deny of `*:send` on Gil at one channel: muted there in every state of the channel, not elsewhere.

**A.6. A workspace of pages.** The organisation keeps its archives under one place that holds nothing else. The leads group is assigned `lead` at the organisation, which includes writing reports. The writers group is assigned `writer` there and is excluded from `report:write` at the archives. Mona is in both groups, Wes is a writer only.

- Mona writes in the archives: allowed, through `lead`. Wes: denied. Wes elsewhere: allowed.
- An exclusion of `report:write` on Mona herself at the archives and an allow on her at the archive of 2024: 2019, denied. 2024, allowed. An archive created later, denied. An active report in a project, allowed, through `lead`.
- Zoe is allowed `report:*` and excluded from `report:write` at the organisation: read, allowed. Write, denied.
- Hal, a writer only, joins the leads group and grants are issued again: writes in the archives.

**A.7. A cluster.** Namespaces sit under the cluster. Groups come from outside, supplied with every question.

- A group assigned a role in one namespace: nothing in another namespace. The same group assigned at the cluster: every namespace.
- A subject the application reports no group for: nothing, however many bindings its groups have.
- Alice is allowed `report:read` at `/org=acme`: nothing at `/org=acme-x`, a neighbour with a similar name.

## Appendix B. Pseudocode notation

Procedures are written as indented blocks. `for each` iterates a set in no particular order unless the text says "in the order asked" or "from the root down". `return` ends the procedure with its answer and, where the text says so, the statement or value that decided. Sets are written with `union`, `minus` and `intersected with`. `a in S` tests membership. Names in `code` refer to procedures or sets defined in the surrounding text. Nothing in a procedure performs input or output: every statement it reads was handed to it.

## Appendix C. ABNF

Keys of places ([Section 6](#6-place)):

```
place       = root / 1*segment
root        = "/"
segment     = "/" level "=" value
level       = token
value       = 1*( literal / pct-encoded )
literal     = ALPHA / DIGIT / "-" / "." / "_" / "~"
            / "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / ","
            / ";" / "=" / ":" / "@"
pct-encoded = "%" uphex uphex
uphex       = DIGIT / %x41-46
token       = lowalpha *31( lowalpha / DIGIT / "-" / "_" )
lowalpha    = %x61-7A
```

ALPHA and DIGIT are defined in [RFC5234]. `token` is shared with permissions and role names below. `level` never matches `=`, so a segment ends its level at its first `=` and no key parses in two ways. The grammar alone admits keys that are not canonical. A key is canonical when, in addition, `pct-encoded` appears only for an octet that `literal` does not match, the octets of each value once decoded form valid UTF-8 [RFC3629], and no decoded value equals `*`. Every canonical key is a `path-absolute` of [RFC3986].

Permissions and role entries ([Section 5](#5-catalog), [Section 7.1](#71-role-resolution)):

```
permission  = token ":" token
pattern     = "*" / token ":" "*" / "*" ":" token / permission
role-name   = token
role-entry  = pattern / role-name / "-" ( pattern / role-name )
```

A `permission` is a `pattern` without `*`. Every `permission`, `pattern` and `role-name` has exactly one spelling, so each is canonical as written. `*:*` is not a `pattern`.

Times are `1*DIGIT`, integers of seconds ([Section 2](#2-conventions-and-notation)). The text of grants is JSON [RFC8259] under the member order and sorting rules of [Section 8.4](#84-canonical-text), which admit exactly one text for a given set of items.

[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC5234]: https://www.rfc-editor.org/rfc/rfc5234
[RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
[RFC8259]: https://www.rfc-editor.org/rfc/rfc8259
[RFC3986]: https://www.rfc-editor.org/rfc/rfc3986
[RFC3629]: https://www.rfc-editor.org/rfc/rfc3629
