# Attestra dispatch scope gate (Phase 6.3).
#
# Moves the decisions from attestra/runner/gate.py into Rego. Python gathers
# facts from the DB and passes them as `input`; OPA returns `decision`.
# Target authorization + DNS pinning (needs network IO) stays in Python
# (attestra/runner/authorization.py, dns_pin.py) and runs only after allow.
#
# Input shape (all fields required, built by attestra.runner.policy.build_input):
#   asset_found            bool
#   engagement_status      string
#   asset_environment      string
#   authorized_environments [string]
#   today                  "YYYY-MM-DD"
#   window_start / window_end  "YYYY-MM-DD" or null
#   tool, profile          string
#   intrusive_allowed      bool
#   recent_scan_count      number (non-refused runs in the last hour)
#   rate_limit             number (config.SCAN_RATE_PER_ASSET)
#   asset_kind             string
#   ownership_verified     bool
#
# Checks are ordered exactly as in the Phase 1 gate; `reason` is the first failure.
package attestra.scope

import rego.v1

default allow := false

ownership_kinds := {"web_app", "api", "host"}

active_profiles := {"active", "intrusive"}

intrusive_requested if input.profile == "active"

intrusive_requested if {
	input.tool == "nuclei"
	lower(input.profile) in active_profiles
}

checks := [
	{"ok": input.asset_found == true, "reason": "asset not found for engagement"},
	{"ok": input.engagement_status != "halted", "reason": "engagement is halted"},
	{"ok": input.asset_environment in input.authorized_environments, "reason": "no valid authorization for asset environment"},
	{"ok": not_before_window, "reason": "before engagement window"},
	{"ok": not_after_window, "reason": "after engagement window"},
	{"ok": intrusive_ok, "reason": "intrusive/active profile not allowed on asset"},
	{"ok": input.recent_scan_count < input.rate_limit, "reason": "scan rate limit exceeded for asset"},
	{"ok": ownership_ok, "reason": "asset ownership not verified"},
]

default not_before_window := true

not_before_window := false if {
	input.window_start != null
	input.today < input.window_start
}

default not_after_window := true

not_after_window := false if {
	input.window_end != null
	input.today > input.window_end
}

default intrusive_ok := true

intrusive_ok := false if {
	intrusive_requested
	not input.intrusive_allowed
}

default ownership_ok := true

ownership_ok := false if {
	not input.ownership_verified
	input.asset_kind in ownership_kinds
}

required_fields := {
	"asset_found", "engagement_status", "asset_environment", "authorized_environments",
	"today", "window_start", "window_end", "tool", "profile", "intrusive_allowed",
	"recent_scan_count", "rate_limit", "asset_kind", "ownership_verified",
}

# Fail closed: any missing field means the request is refused.
missing_fields := {f | some f in required_fields; not f in object.keys(input)}

default input_valid := false

input_valid if {
	is_object(input)
	count(missing_fields) == 0
	is_boolean(input.asset_found)
	is_boolean(input.intrusive_allowed)
	is_boolean(input.ownership_verified)
	is_array(input.authorized_environments)
	is_number(input.recent_scan_count)
	is_number(input.rate_limit)
	is_string(input.today)
}

failures := ["invalid policy input"] if not input_valid

failures := [c.reason | some c in checks; c.ok != true] if input_valid

allow if {
	input_valid
	count(checks) == 8
	count(failures) == 0
}

decision := {"allow": true, "reason": ""} if allow

decision := {"allow": false, "reason": failures[0]} if not allow
