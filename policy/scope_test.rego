# Policy tests: same cases as tests/runner/test_gate.py (Phase 1), run with `opa test policy/ -v`.
package attestra.scope_test

import rego.v1

import data.attestra.scope

base := {
	"asset_found": true,
	"engagement_status": "active",
	"asset_environment": "staging",
	"authorized_environments": ["staging"],
	"today": "2026-10-14",
	"window_start": "2026-10-10",
	"window_end": "2026-10-20",
	"tool": "zap",
	"profile": "baseline",
	"intrusive_allowed": false,
	"recent_scan_count": 0,
	"rate_limit": 10,
	"asset_kind": "web_app",
	"ownership_verified": true,
}

reason_for(patch) := r if {
	r := scope.decision.reason with input as object.union(base, patch)
}

test_allow_baseline if {
	scope.decision == {"allow": true, "reason": ""} with input as base
}

test_refuse_missing_asset if reason_for({"asset_found": false}) == "asset not found for engagement"

test_refuse_halted if reason_for({"engagement_status": "halted"}) == "engagement is halted"

test_refuse_expired_auth if reason_for({"authorized_environments": []}) == "no valid authorization for asset environment"

test_refuse_wrong_env if reason_for({"asset_environment": "production"}) == "no valid authorization for asset environment"

test_refuse_before_window if reason_for({"today": "2026-10-01"}) == "before engagement window"

test_refuse_after_window if reason_for({"today": "2026-11-30"}) == "after engagement window"

test_open_window_allows if {
	scope.allow with input as object.union(base, {"window_start": null, "window_end": null, "today": "2030-01-01"})
}

test_refuse_active_without_flag if reason_for({"profile": "active"}) == "intrusive/active profile not allowed on asset"

test_refuse_nuclei_intrusive_without_flag if {
	reason_for({"tool": "nuclei", "profile": "Intrusive"}) == "intrusive/active profile not allowed on asset"
}

test_nuclei_active_allowed_with_flag if {
	scope.allow with input as object.union(base, {"tool": "nuclei", "profile": "active", "intrusive_allowed": true})
}

test_zap_intrusive_profile_not_gated if {
	# Phase 1 parity: only "active" is gated for non-nuclei tools.
	scope.allow with input as object.union(base, {"tool": "zap", "profile": "intrusive"})
}

test_refuse_rate_exceeded if reason_for({"recent_scan_count": 10}) == "scan rate limit exceeded for asset"

test_rate_below_limit_allows if {
	scope.allow with input as object.union(base, {"recent_scan_count": 9})
}

test_refuse_unverified_ownership if reason_for({"ownership_verified": false}) == "asset ownership not verified"

test_repo_skips_ownership if {
	scope.allow with input as object.union(base, {"ownership_verified": false, "asset_kind": "repo"})
}

test_order_halted_before_window if {
	reason_for({"engagement_status": "halted", "today": "2026-11-30"}) == "engagement is halted"
}

test_missing_input_denies if {
	not scope.allow with input as {}
}

test_missing_input_reason if {
	scope.decision == {"allow": false, "reason": "invalid policy input"} with input as {}
}

test_missing_one_field_denies if {
	scope.decision.reason == "invalid policy input" with input as object.remove(base, {"ownership_verified"})
}

test_wrong_type_denies if reason_for({"recent_scan_count": "0"}) == "invalid policy input"
