import type { ExpectedIssue, IssueCode } from "../../types.ts";

export function malformed(...path: (string | number)[]): ExpectedIssue {
  return issue("ERR_AUTHZ_MALFORMED", path);
}

export function unknownPermission(...path: (string | number)[]): ExpectedIssue {
  return issue("ERR_AUTHZ_PERMISSION_UNKNOWN", path);
}

export function outside(...path: (string | number)[]): ExpectedIssue {
  return issue("ERR_AUTHZ_PLACE_OUTSIDE", path);
}

export function roleInvalid(...path: (string | number)[]): ExpectedIssue {
  return issue("ERR_AUTHZ_ROLE_INVALID", path);
}

export function ended(...path: (string | number)[]): ExpectedIssue {
  return issue("ERR_AUTHZ_STATEMENT_ENDED", path);
}

function issue(code: IssueCode, path: (string | number)[]): ExpectedIssue {
  return { code, path };
}
