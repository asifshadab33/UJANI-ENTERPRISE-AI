#!/usr/bin/env python3
"""Validate the shared UJANI model/runtime inventory and task contracts."""
from __future__ import annotations

import copy
import hashlib
import json
import jsonschema
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/model-runtime-inventory-v1.schema.json"
V2_SCHEMA_PATH = ROOT / "schemas/model-runtime-inventory-v2.schema.json"


def validate_self_evolution_schema() -> None:
    schema_path = Path(__file__).resolve().parents[1] / "schemas/self-evolution-proposal-v1.schema.json"
    fixture_path = Path(__file__).resolve().parents[1] / "schemas/test-vectors/self-evolution-proposal-v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["$id"] == "urn:ujani:self-evolution-proposal:v1"
    assert schema["properties"]["schema_version"]["const"] == 1
    validator = jsonschema.Draft202012Validator(schema)
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    validator.validate(fixture)

    # The schema is a structural contract, not an authorization grant.
    # The model must not be able to supply a repository, source revision,
    # proposal ID or writable scope; trusted host code binds those values.
    invalid_path = copy.deepcopy(fixture)
    invalid_path["changes"][0]["path"] = "../outside.rs"
    assert list(validator.iter_errors(invalid_path))

    invalid_digest = copy.deepcopy(fixture)
    invalid_digest["changes"][0]["patch_sha256"] = "not-a-digest"
    assert list(validator.iter_errors(invalid_digest))

    incomplete_line_range = copy.deepcopy(fixture)
    incomplete_line_range["findings"][0].pop("line_end")
    assert list(validator.iter_errors(incomplete_line_range))

    unknown_field = copy.deepcopy(fixture)
    unknown_field["changes"][0]["unreviewed_permission"] = "shell"
    assert list(validator.iter_errors(unknown_field))

    # Authority-bearing fields are supplied only by the trusted host envelope.
    forbidden_values = {
        "proposal_id": "model-proposal-1",
        "target": {
            "repository": "owner/repository",
            "base_ref": "main",
            "source_revision": "a" * 40,
        },
        "scope": ["apps/operator-console"],
    }
    for forbidden_field, value in forbidden_values.items():
        model_claim = copy.deepcopy(fixture)
        model_claim[forbidden_field] = value
        assert list(validator.iter_errors(model_claim))
    print("Self-evolution proposal v1 schema and fixture checks passed.")


EXPECTED_SHARED_ARTIFACTS = {
    "catalogs/local-model-catalog-v1.json": "8f97eeb59d5c6cdf6c07df027eaf587a64184ba6",
    "schemas/model-runtime-inventory-v1.schema.json": "8ff1a1db4700214ba687cd806c449bc1ea7dfdb4",
    "schemas/model-runtime-inventory-v2.schema.json": "87fb02d41ea3eeb58fc63807ee7adada8c7ca0b6",
    "schemas/personal-enterprise-task-contract-v1.schema.json": "566a0d72babd58636a3ef40e55b5c44168776522",
    "schemas/test-vectors/consent-binding-v1.json": "dcd7021560212504810e8438e14efd591e5e657d",
    "schemas/test-vectors/model-runtime-inventory-v1.json": "543d645d0154c9263ff7784ba4e203f54e498c3c",
    "schemas/test-vectors/model-runtime-inventory-v2.json": "d1e583a64f7e00fd6c62aa59a872ed2a5e5226c5",
}


def _git_blob_sha1(path: Path) -> str:
    # Windows checkouts may expand repository LF endings to CRLF.
    # Normalize that working-tree representation before computing the Git blob ID.
    data = path.read_bytes().replace(b"\r\n", b"\n")
    header = b"blob " + str(len(data)).encode("ascii") + bytes((0,))
    return hashlib.sha1(header + data).hexdigest()


def validate_shared_contract_manifest() -> None:
    """Fail CI if either repository drifts from the shared v1 contract artifacts."""
    manifest_path = ROOT / "schemas/shared-contract-manifest-v1.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest.get("manifest_version") == 1
    assert manifest.get("hash_algorithm") == "git_blob_sha1"
    assert manifest.get("artifacts") == EXPECTED_SHARED_ARTIFACTS
    for relative_path, expected_sha in EXPECTED_SHARED_ARTIFACTS.items():
        artifact = ROOT / relative_path
        actual_sha = _git_blob_sha1(artifact)
        assert actual_sha == expected_sha, (
            f"shared contract drift in {relative_path}: "
            f"expected {expected_sha}, got {actual_sha}"
        )
    mirror = ROOT / "apps/operator-console/model-catalog.json"
    assert _git_blob_sha1(mirror) == EXPECTED_SHARED_ARTIFACTS["catalogs/local-model-catalog-v1.json"], (
        f"local model catalogue mirror drift: {mirror.relative_to(ROOT)}"
    )



def _v2_evidence_recent(evidence: dict, now_unix_ms: int, max_age_ms: int) -> bool:
    observed = evidence.get("observed_at_unix_ms")
    return (
        isinstance(observed, int)
        and observed > 0
        and observed <= now_unix_ms + 30_000
        and now_unix_ms - observed <= max_age_ms
    )


def _v2_evidence_claim_usable(evidence: dict, now_unix_ms: int, max_age_ms: int) -> bool:
    return (
        evidence.get("source") not in ("unknown", "estimate")
        and evidence.get("confidence") in ("verified", "reported")
        and _v2_evidence_recent(evidence, now_unix_ms, max_age_ms)
    )


def _v2_inventory_fresh(inventory: dict, now_unix_ms: int, max_age_ms: int) -> bool:
    generated = inventory.get("generated_at_unix_ms")
    return (
        isinstance(generated, int)
        and generated > 0
        and generated <= now_unix_ms + 30_000
        and now_unix_ms - generated <= max_age_ms
    )


def _v2_enterprise_inventory_authorized(inventory: dict) -> bool:
    context = inventory.get("collection_context", {})
    return (
        context.get("scope") == "organisation_enrolled"
        and context.get("owner_consent") == "granted"
        and context.get("organisation_authorisation") == "authorised"
    )


def _v2_model_fits(
    inventory: dict, model: dict, capability_name: str, now_unix_ms: int, max_age_ms: int
) -> bool:
    runtimes = {runtime["runtime_id"]: runtime for runtime in inventory["runtimes"]}
    runtime = runtimes.get(model["runtime_id"])
    if (
        runtime is None
        or runtime["availability"] != "available"
        or not _v2_evidence_claim_usable(runtime["evidence"], now_unix_ms, max_age_ms)
        or model["availability"] != "installed"
        or model["compatibility"]["status"] != "compatible"
        or not _v2_evidence_claim_usable(model["evidence"], now_unix_ms, max_age_ms)
        or not _v2_evidence_claim_usable(model["compatibility"]["evidence"], now_unix_ms, max_age_ms)
    ):
        return False

    platform = inventory["platform"]
    compatibility = model["compatibility"]
    if compatibility["supported_os"] and platform["os"] not in compatibility["supported_os"]:
        return False
    if compatibility["supported_architectures"] and platform["architecture"] not in compatibility["supported_architectures"]:
        return False

    capability = next(
        (item for item in model["capabilities"] if item["name"] == capability_name), None
    )
    if (
        capability is None
        or capability["status"] != "supported"
        or not _v2_evidence_claim_usable(capability["evidence"], now_unix_ms, max_age_ms)
    ):
        return False

    hardware = inventory["hardware"]
    estimates = model["resource_estimates"]
    estimate_evidence = estimates["evidence"]
    has_estimate = any(
        estimates[field] is not None
        for field in (
            "minimum_memory_mb",
            "minimum_accelerator_memory_mb",
            "minimum_storage_bytes",
            "recommended_cpu_threads",
        )
    )
    if has_estimate and not _v2_evidence_recent(estimate_evidence, now_unix_ms, max_age_ms):
        return False
    if estimates["minimum_memory_mb"] is not None:
        available = hardware["memory_available_mb"]
        if available is None or estimates["minimum_memory_mb"] > available:
            return False
    if estimates["minimum_storage_bytes"] is not None:
        free_mb = hardware.get("storage_free_mb")
        if free_mb is None or estimates["minimum_storage_bytes"] > free_mb * 1_048_576:
            return False
    if estimates["recommended_cpu_threads"] is not None:
        cores = hardware["cpu_logical_cores"]
        if cores is None or estimates["recommended_cpu_threads"] > cores:
            return False
    if estimates["minimum_accelerator_memory_mb"] is not None:
        memories = [
            accelerator.get("memory_mb")
            for accelerator in hardware["accelerators"]
            if accelerator.get("memory_mb") is not None
            and _v2_evidence_recent(accelerator["evidence"], now_unix_ms, max_age_ms)
        ]
        if not memories or max(memories) < estimates["minimum_accelerator_memory_mb"]:
            return False
    for kind in compatibility["required_accelerator_kinds"]:
        if not any(item["kind"] == kind for item in hardware["accelerators"]):
            return False
    required_apis = set(compatibility["required_accelerator_apis"])
    if required_apis and not any(
        item.get("runtime_api") in required_apis for item in hardware["accelerators"]
    ):
        return False
    return True


def _v2_select_explicit_model(
    inventory: dict, selected_model_ref: str, capability_name: str, now_unix_ms: int, max_age_ms: int
):
    matches = [model for model in inventory["models"] if model["model_ref"] == selected_model_ref]
    if len(matches) != 1 or not _v2_inventory_fresh(inventory, now_unix_ms, max_age_ms):
        return None
    if not _v2_model_fits(inventory, matches[0], capability_name, now_unix_ms, max_age_ms):
        return None
    return matches[0]


def _v2_references_valid(inventory: dict) -> bool:
    runtime_ids = [runtime["runtime_id"] for runtime in inventory["runtimes"]]
    model_refs = [model["model_ref"] for model in inventory["models"]]
    if len(runtime_ids) != len(set(runtime_ids)) or len(model_refs) != len(set(model_refs)):
        return False
    known_runtimes = set(runtime_ids)
    for model in inventory["models"]:
        names = [item["name"] for item in model["capabilities"]]
        if model["runtime_id"] not in known_runtimes or len(names) != len(set(names)):
            return False
    return True


def validate_model_runtime_inventory_v2() -> None:
    schema = json.loads(V2_SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    assert schema["$id"] == "urn:ujani:model-runtime-inventory:v2"
    assert schema["properties"]["schema_version"]["const"] == 2
    validator = jsonschema.Draft202012Validator(schema)
    fixture_path = V2_SCHEMA_PATH.parent / "test-vectors/model-runtime-inventory-v2.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    validator.validate(fixture)
    assert _v2_references_valid(fixture)
    assert _v2_enterprise_inventory_authorized(fixture)

    now = fixture["generated_at_unix_ms"]
    selected = _v2_select_explicit_model(fixture, "example/model:1.0", "chat", now, 5_000)
    assert selected is not None and selected["model_ref"] == "example/model:1.0"
    assert _v2_select_explicit_model(fixture, "not-installed", "chat", now, 5_000) is None
    assert _v2_select_explicit_model(fixture, "example/model:1.0", "coding", now, 5_000) is None

    # Empty reports and future runtime vendors are valid descriptors, not proof of availability.
    empty_inventory = copy.deepcopy(fixture)
    empty_inventory["runtimes"] = []
    empty_inventory["models"] = []
    validator.validate(empty_inventory)
    assert _v2_references_valid(empty_inventory)
    future_runtime = copy.deepcopy(fixture)
    future_runtime["runtimes"][0]["provider"] = "future.vendor.runtime"
    validator.validate(future_runtime)

    # Unknown/unavailable runtimes, dangling model references and uninstalled models cannot be selected.
    unknown_runtime = copy.deepcopy(fixture)
    unknown_runtime["runtimes"][0]["availability"] = "unknown"
    validator.validate(unknown_runtime)
    assert _v2_select_explicit_model(unknown_runtime, "example/model:1.0", "chat", now, 5_000) is None
    dangling_runtime = copy.deepcopy(fixture)
    dangling_runtime["models"][0]["runtime_id"] = "missing-runtime"
    assert not _v2_references_valid(dangling_runtime)
    downloadable = copy.deepcopy(fixture)
    downloadable["models"][0]["availability"] = "downloadable"
    assert _v2_select_explicit_model(downloadable, "example/model:1.0", "chat", now, 5_000) is None

    # Stale inventory/evidence and resource mismatch are fail-closed.
    assert not _v2_inventory_fresh(fixture, now + 5_001, 5_000)
    stale_evidence = copy.deepcopy(fixture)
    stale_evidence["runtimes"][0]["evidence"]["observed_at_unix_ms"] = now - 5_001
    assert _v2_select_explicit_model(stale_evidence, "example/model:1.0", "chat", now, 5_000) is None
    insufficient_memory = copy.deepcopy(fixture)
    insufficient_memory["hardware"]["memory_available_mb"] = 1_024
    assert _v2_select_explicit_model(insufficient_memory, "example/model:1.0", "chat", now, 5_000) is None

    # Enterprise inventory is unavailable on owner-consent or administrator-policy conflict/revocation.
    for field, value in (("owner_consent", "revoked"), ("owner_consent", "unknown"),
                         ("organisation_authorisation", "revoked"),
                         ("organisation_authorisation", "unknown")):
        denied = copy.deepcopy(fixture)
        denied["collection_context"][field] = value
        validator.validate(denied)
        assert not _v2_enterprise_inventory_authorized(denied)

    personal = copy.deepcopy(fixture)
    personal["collection_context"] = {
        "scope": "personal_local_only",
        "owner_consent": "not_required_local_only",
        "organisation_authorisation": "not_applicable",
        "policy_version": "personal-local-v2",
    }
    validator.validate(personal)
    assert not _v2_enterprise_inventory_authorized(personal)

    # Strict versioning rejects unknown fields; capability unknown is not a positive claim.
    unknown_top_level = copy.deepcopy(fixture)
    unknown_top_level["unrecognised"] = True
    assert list(validator.iter_errors(unknown_top_level))
    unknown_model_field = copy.deepcopy(fixture)
    unknown_model_field["models"][0]["private_prompt"] = "must-not-be-present"
    assert list(validator.iter_errors(unknown_model_field))
    duplicate_capability = copy.deepcopy(fixture)
    duplicate_capability["models"][0]["capabilities"].append(
        copy.deepcopy(duplicate_capability["models"][0]["capabilities"][0])
    )
    assert not _v2_references_valid(duplicate_capability)
    print("Model/runtime inventory v2 schema, policy-boundary and selection checks passed.")


def main() -> None:
    validate_shared_contract_manifest()
    """Validate the model-runtime inventory schema and its bounded fixtures."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "urn:ujani:model-runtime-inventory:v1"
    assert schema["type"] == "object" and schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == 1
    assert set(schema["required"]) == {
        "schema_version", "generated_at_unix_ms", "platform", "hardware", "runtimes", "models"
    }
    device_ref = schema["properties"]["device_ref"]
    assert device_ref["type"] == ["string", "null"]
    assert device_ref["pattern"] == "^[A-Za-z0-9._:-]+$"
    assert schema["properties"]["runtimes"]["maxItems"] <= 16
    assert schema["properties"]["models"]["maxItems"] <= 512
    assert schema["properties"]["hardware"]["properties"]["accelerators"]["maxItems"] <= 32
    evidence = schema["$defs"]["evidence"]
    assert evidence["additionalProperties"] is False
    assert evidence["properties"]["confidence"]["enum"] == [
        "verified", "reported", "estimated", "unknown"
    ]
    fixture_path = SCHEMA_PATH.parent / "test-vectors/model-runtime-inventory-v1.json"
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(fixture)
    assert fixture["schema_version"] == 1
    assert fixture["models"][0]["estimated_min_memory_mb"] == 3_374

    # An empty report is valid but means "not reported", not "no capability".
    empty_inventory = copy.deepcopy(fixture)
    empty_inventory["models"] = []
    validator.validate(empty_inventory)

    # Unknown top-level and nested fields must not be silently accepted.
    unknown_top_level = copy.deepcopy(fixture)
    unknown_top_level["unexpected_field"] = True
    assert list(validator.iter_errors(unknown_top_level))

    unknown_model_field = copy.deepcopy(fixture)
    unknown_model_field["models"][0]["unrecognised_capability_claim"] = True
    assert list(validator.iter_errors(unknown_model_field))
    print("Model/runtime inventory v1 schema and shared fixture checks passed.")

    validate_model_runtime_inventory_v2()
    validate_self_evolution_schema()

    from validate_personal_enterprise_task_contract import main as validate_task_contract
    validate_task_contract()


if __name__ == "__main__":
    main()
