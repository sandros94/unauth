# Working reference: decision invariants, authority rules, authority invariants

Transitional file for the UnAuthZ RFC rewrite. The identifiers (D, A, G) are the ones used in discussion; the RFC renumbers them. "Status" says whether a row is settled for the draft, still to be re-examined, or removed. Vocabulary lives in the Terminology section of [`UNAUTHZ.md`](UNAUTHZ.md) and is not repeated here; open points live in [`ledger.md`](ledger.md).

## D: decision invariants (what "may X do P at T?" guarantees)

| Id | Plain sentence | Status |
| --- | --- | --- |
| D1 | Nothing stated means denied. | settled |
| D2 | A live deny of the asked permission at any place covering the target decides against it. | settled |
| D3 | Deny is exact on what it names and complete on what includes it: denying `event:read` also denies every permission that implies `event:read`, such as `event:manage`; denying `event:manage` leaves `event:read` untouched. | settled |
| D4 | Roles only add; they never deny. A personal deny rule removes a permission, and every permission that implies it, from whatever roles give, and survives any later role change. | settled |
| D5 | Statements at places not covering the target never influence the answer. | settled |
| D6 | Same statements, same question and same clock give the same answer. | settled; which statement is reported as "the reason" when several apply is still open |
| D7 | Width never ranks statements: a narrow allow does not beat a wider deny, nor the reverse. | settled; nearest-first precedence rejected: allows accumulate along the chain, denies veto everywhere |
| D8 | Grants issued from statements answer exactly as checking the statements would, for every target the grants cover; a target outside every base is reported as not covered, never as denied. | settled |

## A: authority rules (who may change statements about others)

| Id | Plain sentence | Status |
| --- | --- | --- |
| A1 | Manage where you change: only a manager of place R changes the statements at R. | settled |
| A2 | Hand out only what you hold: placing an allow or an assignment at R requires the author to hold what it gives at R. Placing a deny or an exclusion of P at R requires the author to hold P at R. | settled |
| A3 | Only members: a statement about X at a place other than the root requires X to be a member of that place per an application hook. | removed from the model: membership is a fact the application supplies, never derived from statements; narrowing whom a manager may place statements about is a SHOULD on the application in Section 12 |
| A4 | Never about yourself: an author never places or removes a statement whose subject is the author's own identifier. Genesis is the one exception. | settled |
| A5 | Removal needs management only: removing any statement at R requires A1 and nothing else. A restriction is protected by placing it wider than the places its target manages. | settled |
| A6 | The root's permanent managers never empty through a change. Only statements about subjects count, never statements about groups. | settled |
| A7 | Genesis: the first permanent allow of `*` placed at the root about one subject while the root has no manager yet. It is the only change made by someone who is not a manager, and it is possible only while the root has no manager. Who triggers it is the application's decision. | settled |
| A8 | Restrictions stay within the author's width: a deny or an exclusion may reach a statement only when that statement's place is covered by the widest place where the author is a manager. | settled |
| A9 | A stored role owned at place O is assignable only at O or under it. | to re-examine |

## G: authority invariants (what the A rules together guarantee)

| Id | Plain sentence | Status |
| --- | --- | --- |
| G1 | No change to the statements places a permission the manager lacks at the place of the change. | settled |
| G2 | The only statement anyone places about themselves is genesis. | settled |
| G3 | No live deny or exclusion reaches a statement placed wider than its author's width. | settled |
| G4 | Once any statement exists, the root has at least one permanent manager; expiry never removes the last one. | settled |
| G5 | Every live statement has someone who may remove it: no hard lock is constructible. | settled; the theorem the RFC proves |
