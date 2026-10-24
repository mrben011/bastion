"""Role to permission mapping. Deny by default: anything not listed here is forbidden.

Service identities and AI agents are separate principal types added in later milestones.
They never share a role with humans.
"""
ROLES = ("platform_admin", "security_analyst", "incident_responder", "auditor")

# Roles that must have MFA enrolled before they can use any other endpoint.
MFA_REQUIRED_ROLES = frozenset({"platform_admin", "incident_responder", "auditor"})

PERMISSIONS: dict[str, frozenset[str]] = {
    "platform_admin": frozenset(
        {"overview:read", "assets:read", "assets:write", "users:read", "users:manage", "audit:read", "audit:verify"}
    ),
    "security_analyst": frozenset({"overview:read", "assets:read"}),
    "incident_responder": frozenset({"overview:read", "assets:read"}),
    "auditor": frozenset({"overview:read", "assets:read", "users:read", "audit:read", "audit:verify"}),
}


def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, frozenset())
