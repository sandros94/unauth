# UnAuthZ: A Model for Place-Scoped Authorization

Status: working draft, not yet versioned. Author: Sandro Circi. Licensed under the MIT licence.

## Abstract

UnAuthZ is a model that grounds authorization implementations of any size, from a flat set of roles in one application to multi-tenant platforms that share resources with guests. It defines how stored statements about subjects answer "may this subject do this, here, now", and how the answers are carried as grants and read away from the statements without losing exactness over time. It addresses two parties, an engine that computes and the application that decides, and says what each must do and nothing of how. Who may write a statement is the application's decision, made with the questions the model answers.

## 1. Introduction

This document specifies the UnAuthZ model. It defines the statements an application keeps about its subjects ([Section 3](#3-terminology)), the catalog of permissions they draw from ([Section 5](#5-catalog)), the places they apply to ([Section 6](#6-place)), how they answer a question ([Section 7](#7-decision-making)), how the answers are carried as grants and read ([Section 8](#8-grants)), what an engine must be handed to answer ([Section 9](#9-what-an-engine-is-handed)), and what the model leaves to the application when statements change ([Section 10](#10-changing-statements)). [Section 4](#4-invariants) lists what the model guarantees. [Section 11](#11-errors) names the refusals. [Section 12](#12-limitations) says what the model does not do, and [Section 13](#13-security-considerations) what an application must do for the guarantees to hold. [Appendix A](#appendix-a-scenarios) gives scenarios with the answers the model requires.

The model does not define how statements are kept, who may write them, how grants are transported, or any programming interface. Those belong to the application.

Three design choices run through the whole text. Nothing is found by scanning: a place is addressed by one key compared byte by byte, and a permission is looked up under a fixed few spellings, its own and the wildcards that include it. Time only ever ends statements: a statement may end, nothing starts later, so what grants carry is exact from the moment they are issued until someone writes. And a read looks only for what it asks: which carried values can bear on a question follows from the catalog alone, so an engine never needs to parse what does not relate to it.

## 2. Conventions and notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/info/bcp14) [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

Place keys, permissions and role entries are given in ABNF [RFC5234] in [Appendix C](#appendix-c-abnf). Grants are a JSON object [RFC8259] under the rules of [Section 8.4](#84-the-grants-object). Procedures are given in the pseudocode notation of [Appendix B](#appendix-b-pseudocode-notation). Examples are JSON or plain prose, they are illustrative and never normative.

Every time in this document, the end of a statement, the time grants are issued, the time of a question, is an integer count of seconds since 1970-01-01T00:00:00Z, ignoring leap seconds, the `NumericDate` of [RFC7519] without fractions. A time is at least 0 and at most 253402300799, the last second of the year 9999, and is written in decimal with no leading zero. The cap lies within the integers on whose value JSON implementations agree exactly [RFC8259], and a count of milliseconds, the commonest mistake of unit, exceeds it for every date after 1978 and is refused instead of being read as a far future. Two times compare as integers.

## 3. Terminology

This document addresses two parties. An **engine** is software that computes according to this document: it resolves roles, answers questions, and issues and reads grants. An engine keeps no statements and performs no input or output. The **application** is the software using an engine: it defines the catalog, keeps the statements and the stored roles, reads for each subject the statements that apply to it, chooses where grants are carried, and decides who may write what. Wherever the application keeps its statements is called its **store** in this document, which requires nothing of it ([Section 9](#9-what-an-engine-is-handed)). Everything this document leaves to the application is outside the model.

A **permission** is one action on one kind of resource, written `resource:action`, for example `event:manage`. A permission says what, it never says where. The character `*` is a **wildcard**: in place of the resource, the action or both, it stands for every value the catalog has there. [Section 5](#5-catalog) defines how wildcards resolve and where they are legal.

A **catalog** is the closed list of permissions an application recognises, together with its **implications**: a permission MAY imply others (`event:manage` implies `event:read`), meaning that it includes them. Holding the implying permission satisfies the implied one, a deny of the implied one reaches every permission that implies it ([Section 5.1](#51-implications)). A catalog also declares the application's presets and MAY declare the structure of its places ([Section 5](#5-catalog)). Nothing in a catalog denies by itself.

A **place** is where a statement applies: a position in a path that starts at the single, unnamed **root** and continues through typed **segments**. A segment pairs a **level**, a kind of place the application declared such as `org` or `unit`, with a value the application assigns to name which org, which unit, and that the model compares only for equality. The **structure** is the catalog's declaration of the levels and of which level may sit under the root and under which other level. A key **fits** a declared structure when the level of each of its segments is declared and may sit under the level before it. The **key** is the string form of a place, for example `/org=org-1/unit=u7`, the root's key is `/`. One place **covers** another when a statement placed at the first applies at the second, and is **wider** than it when it covers it and is not the same place. The **chain** of a place is the ordered list of the places covering it, from the place itself up to the root. [Section 6](#6-place) defines the structure, the key syntax and how coverage is computed. An application whose things need no separation has only the root and writes no place.

A **subject** is whom a statement is about and for whom a question is asked: an identifier the application chooses, with the meaning of the `sub` claim in JSON Web Token (JWT) [RFC7519]. The model does not care what stands behind it: a person, a machine, or a **group** of them such as the members of an organisation or a team. A subject MAY belong to groups, and a statement about a group applies to every subject the application says belongs to it ([Section 7](#7-decision-making)). Which subjects belong to a group is a fact the application keeps and supplies, never one the model derives. The subject and its groups together are the subject's **identifiers**.

A **statement** is one stored assertion about one subject at one place. Every statement has the same shape, `{ kind, subject, value, place?, expiresAt? }`, and `kind` names what it asserts:

- `allow`: makes the subject hold the permission in `value` at the place.
- `assign`: makes the subject hold the role named in `value` at the place.
- `deny`: blocks the subject from the permission in `value` at the place and under it, whatever gives it. Nothing placed lower undoes a deny.
- `exclude`: takes the permission in `value` out of what the subject holds at the place and under it. About a group, it takes out only what that group gave. About the subject itself, it takes out the permission whichever identifier's statement gave it. A statement placed lower gives the permission back there ([Section 7](#7-decision-making)).

`value` is a permission, with wildcards allowed, for `allow`, `deny` and `exclude`, and a role name for `assign`. `place` MAY be absent: an absent place is the root, so an application without places writes none. `expiresAt`, when present, is the time at which the statement ends. A statement is identified by its kind, its subject, its value and its place: at most one statement exists with a given identity, and only its end can change ([Section 10](#10-changing-statements)).

A statement is **live** at a given time when it has no `expiresAt` or `expiresAt` is later than that time. A statement with no `expiresAt` is **permanent**. Nothing in the model starts at a later time: time only ever ends statements.

A **role** is a named list of **entries**, defined once and independent of any place. An entry names a permission, names another role, or, prefixed with `-`, is an **exclusion** that removes what it names from what the other entries give. The same role can be assigned at many places. A role declared in the catalog is a **preset**. A role kept in data is a **stored role**: a name and its entries, which the application keeps and hands to an engine with the statements that assign it. [Section 7.1](#71-role-resolution) defines how a role resolves to permissions.

A **question** is one permission at one **target** place, asked for a subject, of the statements that apply to it, its own and those of the groups it belongs to, at one **time**: "may Alice, a member of `acme-team`, `event:manage` at `/org=org-1`, now?". A statement **relates to** a question when it can change its answer. A **decision** is the answer to a question together with its reason: allowed or not, and which statement determined it ([Section 7](#7-decision-making)).

A subject's **grants** are what the statements about the subject and about its groups amount to, written in a form that is carried outside the statements and read without them. Grants are issued at one time and hold a copy of every statement that can relate to a question about the subject, each with its end, so that a read at any later time answers as the statements would, until someone writes. Grants are issued for one or more **bases**, the places they speak for. A target under no base is **not covered**, and a read says so instead of answering. Several grants of one subject read together are **sets**. [Section 8](#8-grants) defines what grants hold, how they are issued and read, and the object that carries them.

### 3.1. What an engine computes

An engine offers the operations below. Each takes everything it needs as input, reads no store, and either answers or refuses with a reason of [Section 11](#11-errors). [Section 9](#9-what-an-engine-is-handed) says what each must be handed for its answer to be right. This document names them and fixes no programming interface.

- **Load a catalog**: check it and derive its fingerprint ([Section 5](#5-catalog)).
- **Check and build keys**: say whether a key is canonical and fits the structure, build the key of a place under another from a level and a value, give the chain of a key, and say whether one key covers another ([Section 6](#6-place)).
- **Resolve a role** to the permissions it gives ([Section 7.1](#71-role-resolution)).
- **Say what a question needs**: the keys on the chain of its target and the values that relate to its permission, so that an application reads nothing else ([Section 7](#7-decision-making), [Section 9](#9-what-an-engine-is-handed)).
- **Answer a question** from statements ([Section 7](#7-decision-making)).
- **Issue grants** from statements ([Section 8.2](#82-issuing)).
- **Read grants**, one set or several together ([Section 8.3](#83-reading)).
- **Validate a statement** against the catalog, before the application writes it ([Section 10](#10-changing-statements)).
- **Validate a stored role** against the catalog and the roles it names, before the application writes it ([Section 10](#10-changing-statements)).

## 4. Invariants

What the model guarantees, in one place. Each row is a consequence of the sections named with it, which hold the rules and the procedures and cite a row by its identifier where they state it. Every row is about what an engine computes from what it is handed. None is about what an application writes, or about what it leaves out of what it hands over ([Section 9](#9-what-an-engine-is-handed), [Section 10](#10-changing-statements)).

Canonical forms. Permissions, place keys and times each have exactly one text form, defined in this document. That form is the only one an engine reads or writes. Any other representation that a store, an application or a carrier uses, a column layout, a numeric id, a compressed token, MUST round-trip to the canonical form without loss, so that two things are equal exactly when their canonical forms are equal ([Section 6](#6-place)).

Grants are one JSON object whose members this document defines ([Section 8.4](#84-the-grants-object)). The order of its members and lists carries no meaning, an engine ignores the members it does not know at the top of the object, and an engine reads the grants any other engine issued. This is what lets grants fit a size-constrained carrier such as a cookie-borne token without the model knowing about carriers at all.

What an engine guarantees ([Section 7](#7-decision-making), [Section 5.1](#51-implications), [Section 7.1](#71-role-resolution), [Section 8](#8-grants)):

| Id | Guarantee |
| --- | --- |
| G1 | Nothing stated means denied. |
| G2 | A live deny about the subject or about one of its groups, of the asked permission, at any place covering the target, decides against it. Nothing placed lower undoes it. |
| G3 | A deny is exact on what it names and complete on what includes it: denying `event:read` also denies every permission that implies `event:read`, denying `event:manage` leaves `event:read` untouched. |
| G4 | An allow and an assignment only add. An exclusion about a group takes out only what that group gave, so belonging to one more group takes something away only through a deny on that group. An exclusion about the subject itself takes out whatever gave the permission, at its place and under it, and what is given lower stands. |
| G5 | Statements at places not covering the target, and statements that do not relate to the permission asked, never influence the answer. |
| G6 | The same statements, the same question and the same time give the same answer. A question has one time, fixed when it is asked. |
| G7 | The depth of a place never ranks an allow against an allow, nor anything against a deny: allows add up along the chain and a deny blocks from any covering place. Depth matters to an exclusion alone: it takes out what its own place and wider places give, and what a narrower place gives stands. |
| G8 | Grants issued at a time answer, for every target they cover and at every later time, exactly as the statements live at issue would answer at that time. A target outside every base is reported as not covered, never as denied. |
| G9 | A role that cannot be resolved gives nothing, and so does every role that names it, with or without `-`: a role that no longer exists, and a role on a cycle of references. An entry that names such a role is never skipped, since skipping an exclusion would widen the role. |

## 5. Catalog

The catalog is the vocabulary an engine holds without a store. It declares the permissions the application recognises, the implications between them, the presets, and the structure of places when the application chooses to declare it ([Section 6](#6-place)). An application defines it in code or loads it as data ([Section 5.2](#52-catalog-data-and-fingerprint)), and an engine reads it as it was given. Nothing in a catalog is asked of a store.

A resource, an action, a role name and a level of the structure ([Section 6](#6-place)) are each one **token**: a lowercase ASCII letter followed by at most thirty-one lowercase letters, digits, `-` or `_`, as [Appendix C](#appendix-c-abnf) gives it. A permission is a resource and an action joined by `:`. This spelling is the canonical form of [Section 4](#4-invariants), compared byte by byte, and there is no other: `Report:read` is not a permission in another form, it is refused. An application whose vocabulary is spelled otherwise maps it onto tokens where it defines the catalog.

A permission not in the catalog is **unknown**. An engine MUST refuse an unknown permission in the catalog itself, in a question, and in a statement or a stored role it is asked to validate ([Section 10](#10-changing-statements)). A statement or a stored role read from a store that names an unknown permission, because the catalog changed after it was written or because it was written without validation, is **inert**: an allow or an exclusion of it gives or removes nothing, a deny of it blocks nothing, and the rest of the statement or role applies as written. Grants issued before the change are reissued once their catalog fingerprint no longer matches ([Section 8](#8-grants)). Whether such a statement is rewritten or removed is the application's.

This document reserves no name. No permission, no role and no subject means anything the application did not say, and none stands above a deny or an exclusion ([Section 12](#12-limitations)).

The wildcard `*` MAY stand for the resource (`*:read`), for the action (`event:*`) or for both. The wildcard for every permission is written `*`. `*:*` is not a spelling of it, and an engine MUST refuse it. A wildcard resolves, at the time of the check, to every permission the catalog declares that matches it: `*:read` is every declared permission whose action is `read`, not every resource crossed with `read`. A catalog that grows is therefore covered without a new write. A wildcard that matches no declared permission is unknown, as a permission not in the catalog is. Wildcards are legal in statements and in role entries, never in a question or in an implication. No other pattern is recognised.

An engine MUST refuse a catalog that declares the same permission twice, a name that is not a token, an implication whose permissions are not both concrete and declared, a cycle of implications, since two permissions that imply each other are one permission, a structure that declares no level, which `false` says, or in which a level sits under a level that itself sits nowhere, or a preset that references a stored role or breaks a rule of [Section 7.1](#71-role-resolution). A refused catalog defines nothing: an engine has a catalog or has none.

An engine derives from the catalog a **fingerprint** that grants carry, so that an engine refuses grants written for another catalog ([Section 5.2](#52-catalog-data-and-fingerprint)).

### 5.1. Implications

An implication is declared in the catalog, from one permission to another: `report:write` implies `report:read`, since writing a report means reading it first. It means that the first permission includes the second: whoever holds `report:write` also satisfies a question about `report:read`. Implications are transitive, a permission may imply several others and be implied by several others, and both permissions of an implication MUST exist in the catalog.

Because the implying permission includes the implied one, a deny of a permission also denies every permission that implies it, directly or through a chain, since exercising any of those would exercise the denied one. It never denies what the denied permission itself implies: denying `report:write` leaves `report:read` as it was (G3). An exclusion in a role removes the permissions it names and every permission that implies them, for the same reason: the role `["*", "-report:read"]` yields neither `report:read` nor `report:write`. So a deny and an exclusion both reach what includes the named permission, and neither names what it implies. A deny leaves the implied permission to whatever gives it. An exclusion does too, yet a subject who held the implied permission only through the excluded one holds it no longer: with `report:read` given and then excluded, `report:list` goes as well, since nothing is left that gives it. They differ in kind: a deny blocks the action whatever gives it and nothing lower undoes it, an exclusion only withholds what was given, and a narrower allow gives it back.

Example. Catalog: `report:list`, `report:read`, `report:write`, with `report:write` implying `report:read` and `report:read` implying `report:list`. One role, `analyst = ["report:write"]`, for staff who write their own reports, resolved as [Section 7.1](#71-role-resolution) describes. Alice and Bob are both assigned `analyst` at `/org=acme`, Bob also holds a deny of `report:read` there.

| Question at `/org=acme/report=q3` | Alice | Bob |
| --- | --- | --- |
| `report:write` | **allowed**: `analyst` gives it | **denied**: writing would read, and the deny reaches down to it |
| `report:read` | **allowed**: `report:write` implies it | **denied**: the deny names it |
| `report:list` | **allowed**: through the chain | **allowed**: listing does not read, so the deny does not reach up to it |

### 5.2. Catalog data and fingerprint

A catalog is plain data, so that an engine in any language loads the same one. It is one JSON object [RFC8259] with the members below and no others:

- `permissions`: the declared permissions, a list of strings.
- `implies`: an object that maps a permission to the list of permissions it implies directly.
- `presets`: an object that maps the name of a preset to the list of its entries.
- `places`: the structure ([Section 6](#6-place)), or `false` for an application that has no places. The structure is an object that maps a parent to the list of levels that may sit directly under it. The parent is a level, `/` for the root, or `*` for the root and every level.

A member with nothing to declare is absent, at every depth: a permission that implies nothing has no member in `implies`. `places` is the one member whose absence has a meaning of its own: the catalog then says nothing about places, and keys are checked against the grammar alone ([Section 6](#6-place)). How an application writes its catalog in code is its own affair, as long as it converts to this object.

The **fingerprint** is a value that is equal for two catalogs that declare the same things and, short of a collision of the hash, different otherwise. It is computed the way the thumbprint of a key is [RFC7638]:

1. Take the object above. Sort every list and keep each value once. Sort the members of every object by name. Both sorts compare strings by the value of their bytes, never by the collation of a language.
2. Write it as JSON with no whitespace. No string needs an escape, since every name and every value is made of the characters [Appendix C](#appendix-c-abnf) allows in a token, a pattern or a role entry, and of `/`.
3. Hash the octets of that text with SHA-256 [RFC6234].
4. Write the hash in the URL-safe base64 alphabet without padding [RFC4648], which gives 43 characters.

A later revision of this document that changes this computation raises the format revision of grants ([Section 8.4](#84-the-grants-object)).

## 6. Place

A place says where a statement applies. Places form one tree. At the top is the root, which has no name and whose key is `/`. Under it, every place is named by a path of segments, and each segment pairs a level with a value: the level says what kind of place it is (`org`, `unit`), the value says which one (`acme`, `u7`). A statement at a place applies there and everywhere under it.

The catalog MAY declare the **structure**: the level names, and which level may sit under the root and under which other level ([Section 5.2](#52-catalog-data-and-fingerprint)). A level MAY have several child levels, MAY sit under several parents, and MAY nest under itself, so a tree may be as deep as the application wants unless its structure says otherwise. A structure MAY also declare that a level sits under anything, the root and every level, as a folder or a media library does.

A catalog says one of three things about places. It declares a structure, and a key **fits** when the level of each of its segments is declared and may sit under the level before it, the root for the first. It declares that the application has no places, and only the root fits. Or it says nothing, and every canonical key fits: an engine then checks keys against the grammar alone, and the application validates places where it builds them. There is no middle way: a structure declares every level, or no level is checked.

An engine MUST refuse a key that does not fit, wherever it is given one: in a question, in a base, in a statement it is asked to validate ([Section 10](#10-changing-statements)). A statement read from a store at a key that does not fit, because the structure changed after it was written or because it was written without validation, is inert ([Section 5](#5-catalog)): it applies nowhere and is left out of grants. An engine knows nothing about which resources or permissions belong at a level. Whether a given place exists, whether `acme` is a real organisation, is the application's knowledge: it answers that before it asks the engine. Places under the same parent have no order among themselves. One thing has one place at a time: a level that sits under several parents holds different things under each, never one thing with two keys, since a deny at one key would be bypassed at the other.

The **key** is the text of a place, and the only form an engine reads or writes. The root is `/`. Every other key writes its segments from the root down, each as `/`, the level, `=`, the value: `/org=acme/unit=u7`. A `/` starts every segment and appears nowhere else, so a key has as many segments as it has `/` characters. A level never contains `=`, so a segment splits at its first `=`, and a value MAY contain `=`, `:` or any other character that identifiers in the wild use: `/account=did:plc:abc`. [Appendix C](#appendix-c-abnf) gives the grammar.

A level is one token ([Section 5](#5-catalog)). A value is a non-empty sequence of Unicode scalar values, written in UTF-8 [RFC3629] and then percent-encoded as in [RFC3986], in uppercase hexadecimal, for every octet that [Appendix C](#appendix-c-abnf) does not allow literally. An octet that is allowed literally MUST be written literally. One place therefore has exactly one spelling, made of ASCII characters only. No segment can equal `.` or `..`, since every segment holds a `=`, so a URI parser leaves a key as it is [RFC3986].

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

## 7. Decision making

A question is asked for one subject, of the statements that apply to it: those about the subject itself, and those about every group it belongs to, as the application's source of memberships knows them at that moment. The application reads them, and MAY look the memberships up in the same read ([Section 9](#9-what-an-engine-is-handed)). An engine is handed those statements with the subject's own identifier, and nothing else about groups.

An engine takes every statement it is handed as applying to the subject. A statement whose subject is the subject's own identifier is about the subject itself. Any other is about one of its groups, and statements with the same subject are about the same group. That is all an engine knows of groups: it compares identifiers for equality, and knows nothing about who is in which group.

What is handed over must be whole, and nothing more. A group whose statements are left out is a group that does not count, and for a deny that is a block silently missed. A statement about a subject the asker does not belong to, handed over all the same, counts as a group's ([Section 13](#13-security-considerations)).

The same holds wherever statements are handed over: for a question asked of them and for issuing grants. A read of grants needs none, since the grants already hold what every identifier gave ([Section 8](#8-grants)).

A question is answered from the live statements at the places covering the target, and only from those that **relate to** the permission asked. A deny relates to it when it names the asked permission or a permission the asked one implies ([Section 5.1](#51-implications)). An allow relates to it when it names the asked permission or one that implies it, an assignment when its role resolves to one ([Section 7.1](#71-role-resolution)), an exclusion when it takes one out. No other statement can change the answer (G5), and an engine MUST NOT need any other to answer. Which permissions these are follows from the catalog alone, so it is known before any statement is read. Only the assignment of a stored role needs that role's definition to tell.

A question has one time, fixed when it is asked: the application gives it, or names the clock an engine reads once before it decides anything. An engine MUST decide every step of the question against that one time (G6). The same holds for issuing, for a read of grants and for the validation of a statement.

First, the denies. If a live deny about the subject or about one of its groups relates to the question, the answer is denied, whatever is given, and nothing more needs to be read (G2, G3). A deny MAY name a wildcard: it then blocks every permission the wildcard expands to, so a deny of `*` at a place blocks the subject from everything at and under that place.

Second, what is given (G4). Each allow and each assignment about one of the subject's identifiers gives that identifier a set of permissions: what the permission of an allow expands to, or what the role of an assignment resolves to ([Section 7.1](#71-role-resolution)). An exclusion about a group takes out of what that group was given, at the exclusion's place and under it, the permission it names and every permission that implies it. An exclusion about the subject itself takes the same out of what every identifier was given, at its place and under it. An exclusion wins at its own place: what the same place gives is taken out too, exactly as `-` wins inside a role. What a narrower place gives stands, whoever it is about. The answer is allowed when some permission left is the asked one or implies it, and denied when none is (G1).

Depth ranks nothing but an exclusion against what gives (G7), and the walk shows how. Read the chain from the root down to the target, carrying for each identifier what has been given so far of the permissions that satisfy the question. At each place, first add what the allows and assignments there give, then take out what the exclusions there remove. What is left at the target decides.

Two consequences follow. A subject denied a permission at a wide place does not obtain it from an allow at a narrow place inside: a guest who must see one document under a place where they are denied has to lose the deny, not gain an allow. And an exclusion is the tool for "everything except one": excluded at the place that holds twenty archives and allowed at one of them, a subject writes in that one archive and in no other, and in no archive created later.

The decision names the statement that decided: the deny that blocked, or the allow or assignment whose permissions were left and satisfied the question. When several statements would decide alike, an engine names one of them, and this document does not say which.

```
ask(statements, subject, permission, target, now):
  blocking = permission and every permission it implies
  wanted   = permission and every permission that implies it
  for each live deny d in statements at a place on the chain of target:
    if some p in expand(value(d)) is in blocking:
      return denied, d
  carried = empty map from identifier to set of permissions
  for each place K on the chain of target, from the root down to target:
    for each live allow or assignment s in statements at K, about the identifier I:
      carried[I] = carried[I] union (given(s) intersected with wanted)
    for each live exclusion e in statements at K, about an identifier G other than subject:
      carried[G] = carried[G] minus removed(value(e))
    for each live exclusion e in statements at K, about subject:
      for each identifier I: carried[I] = carried[I] minus removed(value(e))
  if some carried set is not empty:
    return allowed, the statement that gave one of its permissions
  return denied
```

`given(s)` is the expansion of the permission of an allow, or the `P` of the role of an assignment ([Section 7.1](#71-role-resolution)). `expand` resolves a wildcard against the catalog in force. `removed(X)` is the expansion of `X` together with every permission that implies one of them. A permission in `wanted` satisfies the question, a permission in `blocking` is what a deny must name to block it.

A question names one permission at one target. An engine MUST refuse a question that names no permission, an unknown permission or a wildcard. Whether an action needs several permissions, all of them or any of them, at one place or at several, is the application's to decide: it asks one question for each and combines the answers itself. Each answer is exact for its own permission, place and time, and the model says nothing of how answers combine.

### 7.1. Role resolution

A role entry is read as follows: an entry prefixed with `-` is an exclusion of what follows the prefix, an entry that is `*` or contains `:` names a permission, possibly with wildcards, and any other entry names a role. What follows `-` is read by the same rule, so `-billing:read` excludes a permission and `-ops` excludes a role: everything the role `ops` resolves to is taken out, with every permission that implies one of them. The `-` prefix is legal only inside a role definition. The order of entries carries no meaning. An exclusion that removes nothing has no effect. A role with no entries is valid and gives nothing. Examples: `support = ["*:read", "-billing:read"]` reads everything except billing, and `manager = ["owner", "-ops"]` holds everything `owner` holds except what `ops` holds. An exclusion removes what it names and every permission that implies it, whether it names a permission or a role, as [Section 5.1](#51-implications) states.

A role that names another role receives what the named role gives, and the named role's exclusions keep applying unless the referencing role names the excluded permission itself, by an exact entry or by a wildcard. Example: `["support", "billing:read"]` reads billing, while `["support", "moderator"]` does not, whatever `moderator` holds. The rule exists so that composing roles never silently gives back what one of them was built to withhold: a withheld permission returns only when the composing role names it. A preset MAY reference presets only. A stored role MAY reference presets and stored roles. A role named after `-` is referenced too, for these rules and for every rule of this document about references.

A role `R` resolves to two sets of concrete permissions: `P`, what the role gives, and `E`, what the role still forbids to roles that reference it. Before resolution every wildcard in the role's own entries is expanded against the catalog in force, so the procedure works on plain sets. `own_includes(R)` are the role's own entries that name a permission, `own_excludes(R)` what its own exclusions remove (for a permission, `removed` of it, for a role, `removed` of every permission in that role's `P`), and `refs(R)` the roles it names without the prefix. `P(ref)` and `E(ref)` are the two sets of a referenced role, computed by the same procedure.

```
resolve(R):
  P_in = union of P(ref) for every ref in refs(R)
  E_in = union of E(ref) for every ref in refs(R)
  P    = ((P_in minus E_in) union own_includes(R)) minus own_excludes(R)
  E    = (E_in minus own_includes(R)) union own_excludes(R)
  return (P, E)
```

A role with no references has `P_in` and `E_in` empty, so `P` is its includes minus its excludes. Every other part of the model that reads a role reads `P` only: the check and the issuing of grants. `E` is consumed by resolution alone. An engine MUST refuse a reference to an unknown role, and a cycle of references, in a stored role it is asked to validate ([Section 10](#10-changing-statements)), a role named after `-` included. A cycle met when a role is read is read as a role that no longer exists, so `resolve` always terminates.

A role that no longer exists when it is read, because the application deleted a stored role or a preset left the catalog, fails closed (G9). An assignment that names it gives nothing. A role with an entry that names it, with or without `-`, gives nothing at all, and neither does a role that references that one: ignoring the one entry would silently widen a role that was built to exclude it. A name that is both a preset and a stored role reads as the preset, so that grants, which carry a preset by its name ([Section 8.1](#81-what-grants-hold)), and the statements read alike. An application SHOULD NOT give a stored role the name of a preset. Stored roles have distinct names. An engine MUST refuse two stored roles of one name, wherever it is handed them: reading either would be a guess.

## 8. Grants

Grants are carried where the application chooses, in a signed token, in a server-side session record, in any store of its own. Where they live and how they travel is the application's decision. What they hold, how they are issued, how they are read and the object that carries them are normative.

### 8.1. What grants hold

Grants are issued for one subject, at one time, from the statements live at that time about the subject's identifiers, its own and those of its groups, as the application's source of memberships knows them. They hold:

1. **The bases**, the places the grants speak for. The root when none is named. A target under no base is not covered.
2. **A copy of every statement that can relate to a question** about the subject: its kind, its value as written, its place, and its end when it has one. A permission is kept as written, wildcards included. A preset is kept by name. A stored role is kept as the permissions it resolved to at issue, written once and referenced from every place where it is assigned.
3. **Bundles.** What a group gave the subject is kept together as a **bundle** when that group also has an exclusion in the grants. Every value of the bundle, and the group's exclusion itself, carries the bundle's number, so that the exclusion closes its own bundle and nothing else. Values outside every bundle are the subject's own or came from groups without exclusions, and an exclusion without a number is the subject's own and reaches everything. Denies carry no number. A bundle number never says which group it was, and the numbers are assigned anew at each issue.
4. **The time they were issued**, so that a read at an earlier time is refused.
5. **The revision of this format and the fingerprint of the catalog** they were written for, so that an engine refuses what it cannot read and says which of the two differs.

Grants hold nothing else about the subject: not the names of its groups, not who placed a statement, not statements that had ended at issue, not statements about other subjects. An application MAY add members of its own to the object that carries the grants, and an engine ignores them ([Section 8.4](#84-the-grants-object)).

Grants freeze what the statements held at issue. A statement that ends later ends in the grants too, because its end travels with it: a value whose end has passed does not count, and nothing else changes. A statement placed or removed later is not in the grants: the delay between such a write and the next issue is the application's choice, through where it keeps its session and for how long. An application that accepts no delay asks the statements directly ([Section 7](#7-decision-making)).

Membership is frozen too. Grants reflect the groups the subject was in when they were issued. Joining or leaving a group afterwards changes nothing until new grants are issued.

### 8.2. Issuing

Issuing takes the subject, the statements that apply to it ([Section 7](#7-decision-making)), the bases and the time of issue, reads those that are live at that time, with the definitions of the stored roles they assign, and writes the grants. A statement is kept when its place lies on the chain of a base or under a base. Nothing is folded: a statement above a base stays at its own place. A statement that gives, blocks and takes out nothing is left out too: an inert one ([Section 5](#5-catalog)), or an assignment whose role resolves to no permission.

Each group that has at least one exclusion kept in the grants gets a bundle number of its own, any positive integer. Every value that group gave and every exclusion about it carries that number. No other group has a bundle, and which number a group gets carries no meaning.

Two engines issuing from the same statements for the same subject, bases and time MUST produce grants that read alike: the same answer for every permission, every target and every time. Their text MAY differ.

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

This read gives the answer of the walk of [Section 7](#7-decision-making): a given value counts when it is live, its place covers the target, and no live exclusion that applies to it sits at its place or under it on the chain. A deny on a group blocks every member, so denies belong to no bundle. For every covered target the grants and the statements live at issue agree at every time (G8), and the two readings never diverge before someone writes.

Several sets of one subject MAY be read together, for example a small set for the platform in a cookie and a deep set for a drive kept server side. A target is covered when any set covers it, and it is allowed only when every set covering it allows. Each set alone is exact for the targets it covers, so two sets disagree only when one was issued before a change: requiring every one to allow lets the older set's deny stand, which is the safe side. A set that refuses makes the read refuse. Bases of sets read together SHOULD NOT cover each other, so that no statement is carried twice and reissued twice.

### 8.4. The grants object

Grants are written as one JSON object [RFC8259]. An engine reads the members below and ignores any other member of the object, so an application MAY add members of its own beside them, as a token carries claims of several kinds [RFC7519]. Inside the members below nothing else is allowed. The order of members, of lists and of items carries no meaning, and neither does whitespace. Every number is an integer.

- `v`: the revision of this format, the string `"1"` for this document. A later revision of this document raises it only when a read of grants written under the earlier one would differ.
- `ct`: the fingerprint of the catalog, a string ([Section 5](#5-catalog)).
- `at`: the time of issue.
- `bs`: the bases, a list of canonical keys. Absent when the only base is the root.
- `pl`: the **place table**, a list of canonical keys, the root never among them. Absent when no item names a place.
- `rl`: the **role table**, a list of rows, each row the list of concrete permissions a stored role resolved to. Absent when no stored role is assigned.
- `nt`: the **entries**, an object whose member names are the values carried: a permission or a pattern as written, a preset name, or `#` followed by the index of a row of `rl`.

An entry is an object with up to three members: `a` for what is given, `d` for what is denied, `x` for what is taken out. `d` and `x` appear only in entries whose name is a permission or a pattern. Each member is a list of **items**, and an item is a list of up to three elements: the index of the place in `pl`, or `null` for the root, then the end, or `null` when permanent, then the bundle number. Trailing elements that are `null` MAY be omitted, so `[]` is the root with no end and no bundle, `[3]` is the fourth place of `pl`, `[3,1794819600]` adds an end, and `[null,null,2]` is the root in bundle 2. Each item is read on its own, so the same item written twice changes nothing.

An engine validates the grants it is handed before it answers from them, and MUST refuse them as malformed ([Section 11](#11-errors)) unless all of the following hold:

- The object holds `v`, `ct`, `at` and `nt`, and every member above that is present has the type stated.
- Every key in `bs` and `pl` is canonical and fits the structure, and `pl` does not hold the root.
- Every row of `rl` holds permissions of the catalog and nothing else.
- Every name in `nt` is a permission of the catalog, a pattern that matches one, a preset, or `#` followed by the index of a row that exists.
- Every entry holds `a`, `d` or `x` and nothing else, with `d` and `x` only under a permission or a pattern.
- Every item holds at most three elements: a place index that exists in `pl` or `null`, an end that is a time or `null`, and a bundle number or `null`. A bundle number is an integer from 1 to the largest value a time may take, and an item of `d` holds none.

Grants that hold only some of the entries are grants too. An application MAY hand an engine the entries a question relates to and nothing else, with the tables they index, and the engine validates what it is handed ([Section 9](#9-what-an-engine-is-handed)).

Zoe is allowed `report:*` and excluded from `report:write` at the organisation:

```json
{
  "v": "1",
  "ct": "9f2c…",
  "at": 1794214800,
  "pl": ["/org=acme"],
  "nt": { "report:*": { "a": [[0]] }, "report:write": { "x": [[0]] } }
}
```

A bundle, in one case. Sue's team is assigned `writer` at the organisation and excluded from `report:write` in the archives. Sue herself is allowed `report:write` at the organisation until Friday. Three values come out of this. The team has an exclusion, so what it gave forms bundle 1, while Sue's own allow is in no bundle:

```
writer         given      at /org=acme                 bundle 1    from the team
report:write   given      at /org=acme, ends Friday    no bundle   from Sue herself
report:write   taken out  at /org=acme/area=archives   bundle 1    the team's exclusion
```

The grants are issued on Monday 2026-11-09 at 09:00 UTC, `1794214800`. Her allow ends on Friday 2026-11-13 at 00:00 UTC, `1794528000`, so it is live on Thursday and ended on Saturday. A read in the archives closes bundle 1 only: `writer` no longer gives `report:write` there. Sue's own allow is in no bundle, so the exclusion does not touch it, and on Thursday she writes. On Saturday her allow has ended: denied. Had the exclusion been placed on Sue herself, it would carry no number and would take the permission out of everything, her own allow included. A group with no exclusion anywhere in the grants has no bundle, and its values look exactly like the subject's own.

The same grants as an object:

```json
{
  "v": "1",
  "ct": "9f2c…",
  "at": 1794214800,
  "pl": ["/org=acme", "/org=acme/area=archives"],
  "nt": {
    "report:write": { "a": [[0, 1794528000]], "x": [[1, null, 1]] },
    "writer": { "a": [[0, null, 1]] }
  }
}
```

Elsewhere in the organisation `writer` still gives `report:write` to Sue on Saturday, since the exclusion covers the archives only.

A flat application with no places writes no `pl` and items of `[]`. Ed, assigned `viewer` permanently and `editor` until next Monday:

```json
{
  "v": "1",
  "ct": "9f2c…",
  "at": 1794214800,
  "nt": { "editor": { "a": [[null, 1794819600]] }, "viewer": { "a": [[]] } }
}
```

An application MAY carry grants in any other form, abbreviated, compressed or split into rows, as long as it converts to this object and back without changing any answer a read gives ([Section 4](#4-invariants)). An engine reads and writes this object only. A later revision of this document MAY define further members, and an application that wants its own names safe from that keeps the grants object under one member of its carrier and its own members beside it.

### 8.5. When grants are issued again

Grants need no reissue for an expiry: every end travels with its value. They are issued again when the statements about the subject or its groups change by a write, when the subject's groups change, when a stored role they carry is edited, when the catalog changes, or when the application moved or removed places they cover ([Section 10](#10-changing-statements)). A read refused for another catalog is the signal for the catalog case. For the others the application decides, from the delay it accepts and the lifetime it gives its session, and it MAY record when statements last changed, to compare with `at` where a read happens anyway.

## 9. What an engine is handed

An engine reads no store. Every operation takes the statements and the stored roles it works on as input, and its answer is exact for that input (G6). Where the application keeps them, in what layout and behind which query, is the application's, and this document requires nothing of it. This section says what each operation must be handed for its answer to be the answer of the statements the application holds.

**A question asked of the statements** needs every live statement about one of the subject's identifiers at a place on the chain of the target ([Section 6.1](#61-coverage)), and the definition of every stored role those statements assign, with the roles it references. Of those statements only the ones that relate to the permission asked can change the answer ([Section 7](#7-decision-making)), so an application MAY read only those: an engine says which values relate to a permission. Every assignment of a stored role is read with them, since only its definition tells whether it relates.

**Issuing grants** needs every live statement about one of the subject's identifiers at a place on the chain of a base or under a base, and the definitions of the stored roles those statements assign ([Section 8.2](#82-issuing)). Nothing narrower will do, since grants answer later any question about a target they cover, without the statements.

**A question asked of grants** needs the grants and nothing else: no statement is read ([Section 8.3](#83-reading)).

What is left out changes an answer in one direction or the other. An allow or an assignment left out can only turn an allowed answer into a denied one. A deny or an exclusion left out, a group's statements among them, can turn a denied answer into an allowed one. A statement about a subject the asker does not belong to, handed over all the same, can turn an answer either way ([Section 13](#13-security-considerations)). An application that narrows what it reads narrows by what the engine says a question needs, never by a rule of its own.

An engine compares keys, permissions and subjects byte by byte and reads their canonical form only ([Section 4](#4-invariants)). A read that folds case, ignores punctuation or matches by a pattern hands an engine the statements of another place or of another subject. The places under a place are found by the range of keys that [Section 6](#6-place) gives, never by a pattern match, since a canonical key may hold characters that a pattern reads as wildcards.

The time of a question is the one the application gave, or the clock the engine read once ([Section 7](#7-decision-making)). An application that leaves ended statements out of what it reads uses that same time, never the clock of its store. A statement that has ended counts for nothing from then on and MAY be dropped.

A statement whose place no longer exists in the application is not an error: an engine never asks whether a place exists.

A statement or a stored role MAY carry members this document does not define, the identifier of a row or a note for example. They are the application's, and an engine ignores them.

## 10. Changing statements

The statements and the stored roles are the application's data, and so is every write to them. This document says how they answer a question. It does not say who may place, remove or edit one, and an engine checks no author: it never sees a write, and whoever can write where the statements are kept can write anything there. A rule on writes that an engine cannot enforce would be a promise this document cannot keep.

An application gates its writes with the questions this document answers. Whether someone may change who holds what at a place is a permission of the application's own, asked like any other, at the place of the change. Whether a writer may hand out more than they hold, write about themselves, restrict a subject who holds more than they do, or stand above every restriction is the application's rule too, and applications differ on each. [Section 13](#13-security-considerations) says what such a rule has to consider.

An engine validates what is written, never who writes it. Asked to **validate a statement**, it MUST refuse a kind that is not one of the four, a subject that is not a non-empty string, a value that is not a permission or a pattern of the catalog, for an assignment a role that is neither a preset nor among the stored roles it was handed, a place that is not canonical or does not fit the structure, and an end that is not a time or is not later than the time of the validation. Asked to **validate a stored role**, it MUST refuse a name or an entry that is not in its canonical form, an unknown permission, a reference to a role that is neither a preset nor among the stored roles it was handed, and a cycle of references ([Section 7.1](#71-role-resolution)). It looks through references: a role is refused too when a stored role it names, directly or through others, holds such a reference or such a cycle. A stored role handed in under the name of the role being validated is the definition it replaces, not a second role of that name. An application SHOULD validate both before it writes.

Validation is not a gate on reading. What an application writes without it is read by the same rules as anything else: an unknown permission or a place that does not fit is inert ([Section 5](#5-catalog), [Section 6](#6-place)), a role that cannot be resolved gives nothing ([Section 7.1](#71-role-resolution)), and anything not in its canonical form is refused as malformed ([Section 11](#11-errors)).

A statement is identified by its kind, its subject, its value and its place ([Section 3](#3-terminology)). Placing a statement whose identity exists replaces its end, and a removal names those four.

An edit of a stored role reaches everyone who holds the role, at every place where it or a role that references it is assigned. Renaming or deleting a stored role that is assigned or referenced changes what those statements mean, and the application decides whether to refuse, to cascade or to rewrite. It reissues the grants that carried the role, since a stored role is carried as the permissions it resolved to when the grants were issued ([Section 8](#8-grants)).

An engine cannot know that a thing moved. A move is the application's: it rewrites the keys of the statements at and under the old place, and issues again the grants that covered the old place or the new one ([Section 8.5](#85-when-grants-are-issued-again)). Until it does, those grants answer as they did before the move.

## 11. Errors

An engine refuses rather than guesses. Every refusal names one of the reasons below, so that an application can tell them apart in its own logic, and the model does not say how a refusal is carried in a given language or what the application does next. A refusal is never one of the answers allowed, denied or not covered.

- **invalid catalog**: the catalog breaks a rule of [Section 5](#5-catalog). The engine has no catalog.
- **unknown permission**: a permission not in the catalog, in a question, or in a statement or a stored role being validated. Statements read from a store that name one are inert, never an error ([Section 5](#5-catalog)).
- **outside the structure**: a canonical key that does not fit the structure, in a question, in a base or in a statement being validated. Statements read from a store at such a key are inert, never an error ([Section 6](#6-place)).
- **malformed**: a key, a permission, a pattern, a role entry or a time that does not match its canonical form, `*:*` and a non-canonical key included, and grants that fail a check of [Section 8.4](#84-the-grants-object).
- **invalid question**: no permission, or a wildcard.
- **invalid role**: a stored role being validated that references an unknown role or holds a cycle ([Section 7.1](#71-role-resolution)), a statement being validated that assigns a role that is neither a preset nor among the stored roles handed in, and two stored roles of one name handed to any operation.
- **already ended**: a statement being validated whose end is not later than the time of the validation.
- **other format**, **other catalog**: grants whose revision or fingerprint is not the engine's own, named apart so that the application knows whether its own code or the engine changed.
- **before issue**: a read of grants at a time earlier than their time of issue.

## 12. Limitations

What the model does not do, with what an application does instead.

**A key is a position, not an identity.** The model knows a thing only by where it sits. When a thing moves, its key and the keys under it change, and the application rewrites the statements there and reissues the grants that covered them ([Section 8](#8-grants), [Section 10](#10-changing-statements)). When a place is deleted and its value used again for another thing, the statements left there apply to the new thing. An application that must tell two things apart over time uses stable identifiers as values and removes the statements of what it deletes.

**Deep trees cost space, and so do many short-lived statements.** A key carries its whole ancestry, and grants write each place once. A subject with many dated shares carries one item per share, and a carrier the size of a cookie holds a few dozen of them, whatever the form. An application with deep trees or many shares carries grants server side, or issues them for a base near the target, and it states the limit of the carrier it chose.

**No rule on who writes.** The model answers questions and checks no author. Who may place, remove or edit a statement or a stored role is the application's rule, gated with a question of its own ([Section 10](#10-changing-statements)).

**Nobody stands above a statement.** No subject is beyond a deny or an exclusion, whatever it holds and wherever it holds it: a subject allowed `*` at the root and denied a permission at a place is denied there. An application that wants an owner whom no statement can lock out answers for that subject in its own code, before it asks a question.

**No restriction on everyone except a few.** A deny on a group blocks every member, and nothing lifts it for some of them. An application that wants exceptions keeps the exempt subjects out of that group.

**No combined questions.** A question names one permission at one place. An application whose action needs several, all of them or any of them, at one place or at several, asks each and combines the answers itself: which combination an action requires is its own rule ([Section 7](#7-decision-making)).

**No conditions.** A statement's only condition is its end. A restriction that depends on the state of a thing is asked as a different permission for that state, named on the resource, such as `archived-report:write`. An attribute of the request, the network or the time of day is the application's to check before it asks.

**No end on a membership.** A group has members as long as the application lists them. Access that must end at a time is given by a statement with an end, about the subject or about the group.

**No rule for the direct children of a place only.** A statement reaches everything under its place. An application that wants a rule for one level gives those things a place of their own.

**No cap cut against what statements give.** The model adds and blocks, it never intersects. A credential that may do less than its user is the application's, outside the statements.

**Recovery is outside the model.** The model keeps no way back. A deny placed too wide blocks whoever it names until it is removed, and removing it is a write like any other: the application decides who may make it, and keeps that path gated on its own.

## 13. Security considerations

**Hand over every statement that applies, and no other.** A deny about a group blocks a subject only when the application reads that group's statements for it. A group left out of a read turns a block into nothing, silently. A statement about a subject the asker does not belong to, read all the same, counts as a group's. An application MUST read the statements about the subject and about every group it belongs to, from the same source of memberships each time, whether that source is a session, a directory or the store, and MUST hand an engine no other.

**One identifier, one actor.** Subjects and groups share one space of identifiers, compared byte by byte. A user able to choose an identifier equal to a group's receives every statement about that group, two spellings of one name are two subjects, and an identifier given to a new actor carries the statements of the old one. An application MUST keep the identifiers of its subjects and of its groups distinct, bring each to one spelling, and never reuse one.

**Ancestry comes from where the thing is.** An engine trusts the ancestry written in a key. A key built from a request alone, from a route or a parameter, lets a caller claim a position its thing does not have and be answered for that position. An application MUST derive the key from where the thing actually is, or check the claimed key in the action's own read of the thing, and MUST NOT take the ancestry from the request alone.

**One spelling per name.** Two spellings of one accented name are two places, and a deny placed at one is missed at the other. An application MUST bring every name to one form before it becomes a value in a key.

**Clock and unit.** A read lifts an expired deny or exclusion on its own. A clock that runs ahead lifts them early, and a time counted in the wrong unit lifts them at once or never. An engine refuses a time above the cap of [Section 2](#2-conventions-and-notation), which a count of milliseconds exceeds. Every time in the model is an integer count of seconds ([Section 2](#2-conventions-and-notation)), an engine applies no leeway, and an application that wants one applies it on its own clock, knowing that it moves denies and allows alike.

**A deny restricts an identity, not content.** A subject denied a permission still obtains whatever the application serves without identification, by asking from another browser, another device or another network. An application that needs content kept from someone MUST NOT serve that content to requests that do not identify themselves.

**Who may edit a role holds what it can give.** Whoever may edit a stored role can make it, and every role built on it, give any permission of the catalog to everyone who holds them. An application gives that right as it would give every permission, and asks it before any edit.

**Whoever may write a statement may give anything.** The model checks no author ([Section 10](#10-changing-statements)). A path that writes a statement on behalf of a caller, with no question of the application's own asked first, hands that caller every permission of the catalog. An application decides, for each such path, what the caller must hold to make that write, whether a caller may write about itself, and whether a caller may restrict a subject who holds more than it does. It asks before it writes, and it treats a refusal as its own.

**What grants reveal.** Grants carry the places and permissions a subject holds or is kept out of, and a number that says which values share a group without naming it. Whoever reads the carrier learns that much, including the key of a place the subject is excluded from. An application that must hide the existence of a place from a subject keeps that subject's grants away from the subject, in a server-side session for example.

**Grants are trusted as given.** An engine reads the grants it is handed. It cannot tell whether they were altered, whether newer ones exist, or whom they were issued for, since grants name no subject. An application MUST carry grants so that they cannot be altered and stay bound to the subject they were issued for, as a signed token or a server-side session does, and MUST NOT read together sets issued for different subjects.

**Not covered and refused are not allowed.** A read that answers not covered, or that refuses, has allowed nothing. An application MUST NOT perform the action on either: it asks another set of grants or the statements, or it declines.

**The catalog is authority.** Changing the catalog changes what subjects hold without any statement being written. A new permission falls under every wildcard that matches it, a new implication widens what every statement naming it gives or blocks, and an edited preset changes for everyone assigned it. No rule of this document checks a change of the catalog. An application SHOULD review one as it would a change to the statements.

**Keys have no bound in the model.** An engine checks a key against its grammar, and against the structure when the catalog declares one, before computing anything. A structure in which no level nests under itself bounds the depth of every key. A value has no bound, and neither has the depth where a level nests under itself, so an application MAY refuse keys over a length or depth it declares, so that a hostile request cannot hand it a chain of thousands of places.

**Gate writes on the statements.** Grants keep answering as the statements stood when they were issued ([Section 8.1](#81-what-grants-hold)), so a subject whose permission to write was removed a minute ago still holds it in grants issued before. An application that gates a write asks the statements, which the write touches anyway.

## 14. References

- RFC 2119, Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, March 1997. [RFC2119]
- RFC 8174, Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, May 2017. [RFC8174]
- RFC 5234, Crocker, D. and P. Overell, "Augmented BNF for Syntax Specifications: ABNF", STD 68, January 2008. [RFC5234]
- RFC 7519, Jones, M., Bradley, J. and N. Sakimura, "JSON Web Token (JWT)", May 2015. [RFC7519]
- RFC 8259, Bray, T., "The JavaScript Object Notation (JSON) Data Interchange Format", STD 90, December 2017. [RFC8259]
- RFC 3986, Berners-Lee, T., Fielding, R. and L. Masinter, "Uniform Resource Identifier (URI): Generic Syntax", STD 66, January 2005. [RFC3986]
- RFC 3629, Yergeau, F., "UTF-8, a transformation format of ISO 10646", STD 63, November 2003. [RFC3629]
- RFC 7638, Jones, M. and N. Sakimura, "JSON Web Key (JWK) Thumbprint", September 2015. [RFC7638]
- RFC 6234, Eastlake 3rd, D. and T. Hansen, "US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)", May 2011. [RFC6234]
- RFC 4648, Josefsson, S., "The Base16, Base32, and Base64 Data Encodings", October 2006. [RFC4648]

## Appendix A. Scenarios

Each scenario lists a few statements and the answers the model gives. The answers hold when asked of the statements and when asked of grants issued from them. Unless a scenario says otherwise, nothing changes over time. Names are illustrative.

**A.1. One person and an assistant, no places.** Ed is allowed `*` at the root. He runs an agent, `assistant`, which is allowed `post:read` and `post:draft`.

- The assistant reads a post: allowed. Drafts one: allowed. Publishes one: denied, nothing gives it.
- Ed publishes a post: allowed.
- The assistant is then allowed `post:publish`: from then on it publishes. Whether the assistant could have written that statement itself is the application's rule ([Section 10](#10-changing-statements)).

**A.2. A code forge.** Organisations hold repositories. Teams are groups. The web team is assigned `writer` at one repository, and Lea is assigned `developer` at one project by name. Mel holds `access:manage` at that project, a permission the application asks before it lets anyone change access there, and her grants live in a cookie the application accepts for an hour.

- A member of the web team writes in that repository: allowed. In another repository: denied, nothing gives it there.
- Lea, anywhere under her project: whatever `developer` gives, since an assignment reaches everything under its place.
- Mel's `access:manage` is removed. A minute later the application asks the statements whether she may change access: denied. In the same minute it reads the project from her cookie: allowed, within the delay the application chose. An application gates its writes on the statements for this reason ([Section 13](#13-security-considerations)).

**A.3. A cloud account tree.** The platform's owner is allowed `*` at the root. Every subject of the organisation `acme` is in its members group. Tom is allowed `*` at `acme` and is in that group.

- A deny of `audit-log:delete` is placed on the members group at `acme`. Tom deletes an audit log: denied, whatever gives it. A member who joins next month: denied. The owner's own people, outside the group and allowed at the root: allowed.
- A deny of `report:read` is placed on the owner at `acme`. The owner reads a report at `acme`: denied, although allowed `*` at the root. At another organisation: allowed. Nobody stands above a statement ([Section 12](#12-limitations)).
- Dan is allowed `*` at `acme` and denied `report:read` in its archives. Dan reads a report in the archives: denied. Elsewhere in `acme`: allowed. With an exclusion in place of the deny, an allow of `report:read` on Dan at one archive gives it back there.

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

**A.7. A cluster.** Namespaces sit under the cluster. Groups come from outside: the application reads their statements with every question.

- A group assigned a role in one namespace: nothing in another namespace. The same group assigned at the cluster: every namespace.
- A subject the application reports no group for: nothing, however many bindings its groups have.
- Alice is allowed `report:read` at `/org=acme`: nothing at `/org=acme-x`, a neighbour with a similar name.

## Appendix B. Pseudocode notation

Procedures are written as indented blocks. `for each` iterates a set in no particular order unless the text says "from the root down". `return` ends the procedure with its answer and, where the text says so, the statement or value that decided. Sets are written with `union`, `minus` and `intersected with`. `a in S` tests membership. Names in `code` refer to procedures or sets defined in the surrounding text. Nothing in a procedure performs input or output: every statement it reads was handed to it.

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

ALPHA and DIGIT are defined in [RFC5234]. `token` is shared with permissions and role names below. `level` never matches `=`, so a segment ends its level at its first `=` and no key parses in two ways. The grammar alone admits keys that are not canonical. A key is canonical when, in addition, `pct-encoded` appears only for an octet that `literal` does not match, and the octets of each value once decoded form valid UTF-8 [RFC3629]. Whether a canonical key fits the structure is a separate check ([Section 6](#6-place)). Every canonical key is a `path-absolute` of [RFC3986].

Permissions and role entries ([Section 5](#5-catalog), [Section 7.1](#71-role-resolution)):

```
permission  = token ":" token
pattern     = "*" / token ":" "*" / "*" ":" token / permission
role-name   = token
role-entry  = pattern / role-name / "-" ( pattern / role-name )
```

A `permission` is a `pattern` without `*`. Every `permission`, `pattern` and `role-name` has exactly one spelling, so each is canonical as written. `*:*` is not a `pattern`.

Times ([Section 2](#2-conventions-and-notation)):

```
time        = "0" / ( %x31-39 *DIGIT )
```

A `time` is an integer count of seconds with no leading zero, at most 253402300799.

Grants are a JSON object [RFC8259] with the members of [Section 8.4](#84-the-grants-object).

[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC8174]: https://www.rfc-editor.org/rfc/rfc8174
[RFC5234]: https://www.rfc-editor.org/rfc/rfc5234
[RFC7519]: https://www.rfc-editor.org/rfc/rfc7519
[RFC8259]: https://www.rfc-editor.org/rfc/rfc8259
[RFC3986]: https://www.rfc-editor.org/rfc/rfc3986
[RFC3629]: https://www.rfc-editor.org/rfc/rfc3629
[RFC7638]: https://www.rfc-editor.org/rfc/rfc7638
[RFC6234]: https://www.rfc-editor.org/rfc/rfc6234
[RFC4648]: https://www.rfc-editor.org/rfc/rfc4648
