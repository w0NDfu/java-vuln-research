from __future__ import annotations

import csv

from java_vuln_research.common.inventory import (
    inventory_codeql_databases,
    inventory_datasets,
)


def test_inventory_discovers_java_dataset_and_ready_database(tmp_path) -> None:
    dataset_root = tmp_path / "datasets"
    project = dataset_root / "CWE-Bench-Java" / "sample"
    project.mkdir(parents=True)
    (project / "pom.xml").write_text("<project/>", encoding="utf-8")
    dataset_csv = tmp_path / "dataset.csv"

    dataset_rows = inventory_datasets(dataset_root, dataset_csv)

    assert dataset_rows
    assert dataset_csv.is_file()

    db_root = tmp_path / "dbs"
    database = db_root / "sample"
    (database / "db-java").mkdir(parents=True)
    (database / "codeql-database.yml").write_text(
        "primaryLanguage: java\nsourceLocationPrefix: /workspace/sample\n",
        encoding="utf-8",
    )
    db_csv = tmp_path / "db.csv"

    db_rows = inventory_codeql_databases(db_root, db_csv)

    assert db_rows[0]["db_ready"] is True
    with db_csv.open(encoding="utf-8", newline="") as handle:
        persisted = list(csv.DictReader(handle))
    assert persisted[0]["language"] == "java"

