package platform.authz

import future.keywords.if
import future.keywords.in

# ──────────────────────────────────────────────────────────────────
# RBAC POLICY: Tool authorization
#
# This policy is evaluated by the policy engine before any tool call.
# Input shape:
#   input.user.role         string
#   input.user.org_id       string
#   input.tool.name         string
#   input.tool.category     string
#   input.task.id           string
#   input.action.is_bulk    bool
#   input.action.risk_score float
# ──────────────────────────────────────────────────────────────────

default allow = false
default deny_reason = "policy_default_deny"

# Allowed role → tool category matrix.
role_tool_permissions := {
    "platform_admin":   {"read", "write", "compute", "network", "browser", "destructive"},
    "org_admin":        {"read", "write", "compute", "network", "browser"},
    "operator":         {"read", "compute", "network", "browser"},
    "hitl_reviewer":    {"read"},
    "auditor":          {"read"},
    "plugin_developer": set(),
}

# Allow if: user role has permission for this tool category.
allow if {
    permitted_categories := role_tool_permissions[input.user.role]
    input.tool.category in permitted_categories
    not is_high_risk_without_approval
    not is_bulk_without_approval
    not is_denied_domain
}

# Deny bulk operations for non-admin roles unless explicit permission granted.
is_bulk_without_approval if {
    input.action.is_bulk == true
    not input.user.role in {"platform_admin", "org_admin"}
}

# Require HITL for risk scores above threshold.
is_high_risk_without_approval if {
    input.action.risk_score >= 0.6
    not input.hitl.approved == true
}

# Deny list of tool names that are globally forbidden.
globally_denied_tools := {
    "exec_shell",
    "run_arbitrary_code",
    "bypass_security",
    "captcha_solve",       # Anti-abuse
    "credential_harvest",
    "port_scan",
    "vulnerability_scan",
}

is_denied_domain if {
    input.tool.name in globally_denied_tools
}

# Destructive tools always require HITL approval regardless of role.
deny_reason := "destructive_tool_requires_hitl" if {
    input.tool.category == "destructive"
    not input.hitl.approved == true
}

# Hard block: no role can use globally denied tools.
deny_reason := "tool_globally_denied" if {
    input.tool.name in globally_denied_tools
}

deny_reason := "insufficient_role_for_tool_category" if {
    permitted_categories := role_tool_permissions[input.user.role]
    not input.tool.category in permitted_categories
}

# ──────────────────────────────────────────────────────────────────
# COMPLIANCE POLICY: URL access
# ──────────────────────────────────────────────────────────────────
package platform.compliance

import future.keywords.if
import future.keywords.in

default url_allowed = false

# Private IP ranges — always blocked (SSRF prevention).
private_ip_prefixes := [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.", "169.254.", "0.", "::1",
]

is_private_ip if {
    some prefix in private_ip_prefixes
    startswith(input.resolved_ip, prefix)
}

# Blocked schemes.
allowed_schemes := {"https", "http"}

url_allowed if {
    input.scheme in allowed_schemes
    not is_private_ip
    not input.domain in data.denied_domains
    not input.robots_disallowed == true
}

deny_reason := "ssrf_private_ip" if {
    is_private_ip
}

deny_reason := "scheme_not_allowed" if {
    not input.scheme in allowed_schemes
}

deny_reason := "domain_in_deny_list" if {
    input.domain in data.denied_domains
}

deny_reason := "robots_txt_disallowed" if {
    input.robots_disallowed == true
}

# ──────────────────────────────────────────────────────────────────
# AUDIT POLICY: What events must always be logged
# ──────────────────────────────────────────────────────────────────
package platform.audit

import future.keywords.if
import future.keywords.in

# These action patterns always require an audit event. The audit service
# evaluates this policy to determine if a missing log should trigger an alert.
required_audit_actions := {
    "task.create",
    "task.cancel",
    "task.complete",
    "task.fail",
    "tool.execute",
    "tool.blocked",
    "hitl.review.submitted",
    "hitl.review.decided",
    "security.injection_detected",
    "security.ssrf_blocked",
    "compliance.robots_blocked",
    "system.started",
    "system.stopped",
    "auth.token.issued",
    "auth.token.revoked",
    "policy.modified",
    "plugin.submitted",
    "plugin.approved",
    "user.role_changed",
}

must_audit if {
    input.action in required_audit_actions
}
