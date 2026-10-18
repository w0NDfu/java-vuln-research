"""Keep distinct judge inputs from sharing an output filename or verdict ID."""
from collections import Counter
from dataclasses import replace
import hashlib
import json


def unique_records(records):
    counts = Counter(r.fingerprint for r in records)
    occurrences, output = Counter(), []
    for record in records:
        if counts[record.fingerprint] == 1:
            output.append(record)
            continue
        payload = json.dumps(record.to_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode()).hexdigest()[:12]
        key = (record.fingerprint, digest)
        occurrences[key] += 1
        output.append(replace(record, fingerprint=f"{record.fingerprint}--{digest}-{occurrences[key]}",
                              metadata={**record.metadata, "repro_original_fingerprint": record.fingerprint}))
    if len({r.fingerprint for r in output}) != len(output):
        raise RuntimeError("Judge input identity collision; no model requests made")
    return output
