"""Evidence-grounded incident narrative with an optional local Granite endpoint."""
from __future__ import annotations

import json
import os
from urllib.error import URLError
from urllib.request import Request, urlopen

from .correlation import Incident


def deterministic_investigation(incident: Incident) -> list[dict[str, object]]:
    """Return cautious conclusions, each with the IDs that support it."""
    items = incident.evidence
    valid_ids = {item.evidence_id for item in items}
    by_id = {item.evidence_id: item for item in items}
    claims: list[dict[str, object]] = []
    def add(text: str, predicate) -> None:
        refs = [item.evidence_id for item in items if predicate(item)]
        if refs:
            claims.append({"conclusion": text, "evidence_ids": refs})

    for item in items:
        attrs = item.attributes
        if item.event_type == "PROGRAM_CHANGE":
            program = attrs.get("program_name", item.target)
            reference = attrs.get("change_reference", "not supplied")
            status = attrs.get("approval_status", "not recorded")
            baseline = attrs.get("baseline_status", "not recorded")
            add(f"Program {program} change {reference} is recorded with approval status {status} and baseline status {baseline}.",
                lambda event, evidence_id=item.evidence_id: event.evidence_id == evidence_id)
        elif item.event_type == "SUSPICIOUS_SENSITIVE_ACCESS":
            sources = [evidence_id for evidence_id in attrs.get("source_evidence_ids", [])
                       if evidence_id in valid_ids]
            refs = [item.evidence_id, *sources]
            if sources:
                claims.append({"conclusion": item.summary, "evidence_ids": list(dict.fromkeys(refs))})
        elif item.event_type == "BATCH_INTEGRITY_MISMATCH":
            source_id = attrs.get("batch_evidence_id")
            refs = [item.evidence_id]
            if source_id in valid_ids:
                refs.append(source_id)
            claims.append({"conclusion": item.summary, "evidence_ids": refs})
        elif item.event_type == "SETTLEMENT_CONSUMER_QUEUED":
            dataset_id = attrs.get("source_dataset_evidence_id")
            if dataset_id in valid_ids:
                dataset = by_id[dataset_id]
                integrity = next((event for event in items
                                  if event.event_type == "BATCH_INTEGRITY_MISMATCH"), None)
                refs = [dataset_id, item.evidence_id]
                impact_text = (f"Output dataset {dataset.target} is linked to downstream consumer "
                               f"{attrs.get('consumer', item.actor)}. If consumed, the recorded shortfall could "
                               "affect settlement completeness; the evidence does not establish that settlement "
                               "executed or that any payment was missed.")
                if integrity:
                    refs.append(integrity.evidence_id)
                    discrepancy = integrity.attributes.get("record_discrepancy")
                    if discrepancy is not None:
                        discrepancy_text = f"{int(discrepancy):,}"
                        impact_text = (f"Output dataset {dataset.target} is linked to downstream consumer "
                                       f"{attrs.get('consumer', item.actor)}. If consumed, the recorded "
                                       f"{discrepancy_text}-record shortfall could affect settlement completeness; "
                                       "the evidence does not establish that settlement executed or that any "
                                       "payment was missed.")
                claims.append({"conclusion": impact_text, "evidence_ids": list(dict.fromkeys(refs))})

    # State a plausible sequence as a hypothesis, with the causal limitation explicit.
    for integrity in (event for event in items if event.event_type == "BATCH_INTEGRITY_MISMATCH"):
        attrs = integrity.attributes
        program_id = attrs.get("program_evidence_id")
        program = by_id.get(program_id)
        access = next((event for event in items
                       if event.event_type == "SUSPICIOUS_SENSITIVE_ACCESS"
                       and event.attributes.get("business_process") == "Payment settlement"), None)
        batch_id = attrs.get("batch_evidence_id")
        if (program and access and program.attributes.get("business_process") == "Payment settlement"
                and batch_id in valid_ids):
            access_refs = [evidence_id for evidence_id in access.attributes.get("source_evidence_ids", [])
                           if evidence_id in valid_ids]
            refs = [program.evidence_id, access.evidence_id, *access_refs,
                    integrity.evidence_id, batch_id]
            discrepancy = attrs.get("record_discrepancy")
            amount = (f"the {int(discrepancy):,}-record shortfall"
                      if discrepancy is not None else "the record shortfall")
            claims.append({
                "conclusion": (f"Hypothesis for investigation: the unapproved program change and baseline-flagged "
                               f"payment-data access are plausible leads for {amount}. Their recorded sequence "
                               "does not prove either event caused the batch discrepancy."),
                "evidence_ids": list(dict.fromkeys(refs)),
            })

    add("Repeated access attempts against a restricted target were denied.",
        lambda e: e.event_type == "AUTH_FAILURE_BURST")
    add("A privilege or security configuration change was recorded; the event does not establish who approved it.",
        lambda e: e.event_type == "PRIVILEGE_CHANGE")
    add("An unscheduled batch job was started.", lambda e: e.event_type == "UNSCHEDULED_JOB")
    add("A data-integrity check reported a checksum mismatch; the evidence does not establish the cause.",
        lambda e: e.event_type == "CHECKSUM_MISMATCH")
    add("A successful restricted-data read was recorded.",
        lambda e: e.event_type == "RESTRICTED_READ")
    if len(items) > 1:
        claims.append({
            "conclusion": f"{len(items)} events are connected by identity, resource, or explicit evidence dependencies within the configured correlation window.",
            "evidence_ids": [item.evidence_id for item in items],
        })
    return claims


def investigate(incident: Incident, use_granite: bool = False,
                endpoint: str | None = None, model: str | None = None,
                timeout: float = 8.0) -> dict[str, object]:
    """Use optional local Ollama-compatible Granite; validate citations, else fall back."""
    fallback = deterministic_investigation(incident)
    if not use_granite:
        return {"provider": "deterministic", "claims": fallback, "note": "No model requested."}
    endpoint = (endpoint or os.getenv("SENTINEL_GRANITE_URL", "http://127.0.0.1:11434/api/generate")).strip()
    model = model or os.getenv("SENTINEL_GRANITE_MODEL", "granite3.3:2b")
    evidence = [{"id": item.evidence_id, "time": item.occurred_at, "type": item.event_type,
                 "actor": item.actor, "target": item.target, "outcome": item.outcome,
                 "summary": item.summary, "attributes": item.attributes} for item in incident.evidence]
    prompt = ("Investigate only the supplied synthetic evidence. Return a short JSON object with a claims array; "
              "each claim has conclusion and evidence_ids containing only supplied IDs. Do not infer causality or "
              "approval without evidence. Evidence: " + json.dumps(evidence))
    try:
        body = json.dumps({"model": model, "prompt": prompt, "stream": False, "format": "json"}).encode()
        request = Request(endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        generated = json.loads(payload.get("response", "{}"))
        claims = generated.get("claims")
        valid_ids = {item.evidence_id for item in incident.evidence}
        if not isinstance(claims, list) or not claims:
            raise ValueError("Granite response has no claims")
        for claim in claims:
            if not isinstance(claim, dict) or not isinstance(claim.get("conclusion"), str):
                raise ValueError("Malformed claim")
            refs = claim.get("evidence_ids")
            if not isinstance(refs, list) or not refs or not set(refs).issubset(valid_ids):
                raise ValueError("Claim contains missing or unknown evidence references")
        return {"provider": f"local Granite ({model})", "claims": claims,
                "note": "Model output is optional and restricted to citations from this incident's evidence."}
    except (OSError, URLError, TimeoutError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        return {"provider": "deterministic fallback", "claims": fallback,
                "note": f"Local Granite unavailable or response invalid ({type(exc).__name__}); deterministic findings shown."}
