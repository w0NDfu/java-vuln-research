"""Stage identities include input bytes; failed attempts never overwrite evidence."""
from pathlib import Path
from .io import read, write, digest, file_hash, now


class Stages:
    def __init__(self, root, resume=False):
        self.root, self.resume = Path(root), resume
        self.root.mkdir(parents=True, exist_ok=resume)

    def run(self, name, inputs, action):
        directory = self.root / name
        directory.mkdir(parents=True, exist_ok=True)
        identity = digest(inputs)
        receipt = directory / "receipt.json"
        if receipt.exists():
            old = read(receipt)
            if not self.resume or old["identity"] != identity:
                raise ValueError("Stage configuration/input changed or explicit --resume missing: " + name)
            if old["status"] == "complete":
                for relative, expected in old["outputs"].items():
                    if file_hash(directory / relative) != expected:
                        raise ValueError("Checkpoint output changed: " + name + "/" + relative)
                return directory / old["result"]
        prior = list(directory.glob("attempt-*"))
        attempt = directory / f"attempt-{len(prior) + 1:04d}"
        attempt.mkdir(exist_ok=False)
        metadata = {"identity": identity, "inputs": inputs, "status": "running", "started_at": now(), "attempt": attempt.name}
        write(receipt, metadata)
        try:
            result = Path(action(attempt))
            if not result.is_relative_to(attempt) or not result.is_file(): raise ValueError("Stage output missing")
            outputs = {p.relative_to(directory).as_posix(): file_hash(p) for p in attempt.rglob("*") if p.is_file()}
            metadata.update(status="complete", finished_at=now(), result=result.relative_to(directory).as_posix(), outputs=outputs)
        except BaseException as exc:
            metadata.update(status="interrupted" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else "failed",
                            finished_at=now(), error_type=type(exc).__name__)
            write(attempt / "failure.json", metadata)
            raise
        finally:
            write(receipt, metadata)
        return result
