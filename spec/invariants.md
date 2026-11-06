# Working reference: decision invariants, authority rules, authority invariants

Transitional file for the UnAuthZ RFC rewrite. The identifiers (D, A, G) are the ones used in discussion; the RFC renumbers them. "Status" says whether a row is settled for the draft, still to be re-examined, or removed. Vocabulary lives in the Terminology section of [`UNAUTHZ.md`](UNAUTHZ.md) and is not repeated here; open points live in [`ledger.md`](ledger.md).

## D: decision invariants (what "may X do P at T?" guarantees)

| Id | Plain sentence | Status |
| --- | --- | --- |
| D1 | Nothing stated means denied. | settled |
| D2 | A live deny of the asked permission at any place covering the target decides against it. | settled |
| D3 | Deny is exact: denying `event:manage` does not deny `event:read`; implications never deny. | settled |
| D4 | Roles only add; they never deny. A personal deny rule removes one permission from whatever roles give, and survives any later role change. | settled |
| D5 | Statements at places not covering the target never influence the answer. | settled |
| D6 | Same statements, same question and same clock give the same answer. | settled; which statement is reported as "the reason" when several apply is still open |
| D7 | Width never ranks statements: a narrow allow does not beat a wider deny, nor the reverse. | settled; nearest-first precedence rejected: allows accumulate along the chain, denies veto everywhere |
| D8 | Grants issued from statements answer exactly as checking the statements would. | settled |

## A: authority rules (who may change statements about others)

| Id | Plain sentence | Status |
| --- | --- | --- |
| A1 | Manage where you change: only a manager of place R changes the statements at R. | settled |
| A2 | Hand out only what you hold: placing an allow or deny of P, or assigning a role, at R requires the manager to hold P (every P of the role) at R. | settled |
| A3 | Only members: a statement about X at a place other than the root requires X to be a member of that place per an application hook. | removed from the model: membership is a fact the application supplies, never derived from statements; narrowing whom a manager may place statements about is a SHOULD on the application in Section 12 |
| A4 | Never yourself: no manager places a statement about themselves; removing their own is allowed. | to re-examine |
| A5 | Removal needs management only: removing any statement at R requires A1 and nothing else; a restriction is protected by placing it wider. | to re-examine |
| A6 | The root's permanent managers never empty through an operation. | settled; no dedicated term for that set, the invariant is stated over "managers of the root" |
| A7 | Genesis: placing a permanent allow rule of the wildcard permission `*` (every permission, resolved per check) at the root while it has no manager; closes once a manager exists; who triggers it is application logic. | settled; the word is `genesis`; no reserved role name |
| A8 | Restrictions come from at least as wide a place: a deny of P on X at R is refused when X holds P from a place strictly wider than R. | to re-examine: as written it also refuses the wider manager who granted P and wants "everywhere except R"; candidate restatement keyed on the author's width, see ledger Section 10 |
| A9 | A stored role owned at place O is assignable only at O or under it. | to re-examine |

## G: authority invariants (what the A rules together guarantee)

| Id | Plain sentence | Status |
| --- | --- | --- |
| G1 | No change to the statements places a permission the manager lacks at the place of the change. | settled |
| G2 | The only statement anyone places about themselves is genesis. | depends on A4 |
| G3 | No live deny of P on X at R was placed while X held P from wider than R. | depends on A8 |
| G4 | Once any statement exists, the root has at least one permanent manager; expiry never removes the last one. | settled |
| G5 | Every live statement has someone who may remove it: no hard lock is constructible. | settled; the theorem the RFC proves |
