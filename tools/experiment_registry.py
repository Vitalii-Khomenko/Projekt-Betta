"""SQLite-backed research run registry for Betta-Morpho experiments."""
from __future__ import annotations

import argparse
import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from tools.artifact_schema import utc_now_iso
except ImportError:
    from artifact_schema import utc_now_iso

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY_PATH = ROOT_DIR / "data" / "experiments.db"


@dataclass(frozen=True)
class RegistryArtifact:
    role: str
    path: str
    artifact_family: str = ""


class ExperimentRegistry:
    def __init__(self, db_path: str | Path = DEFAULT_REGISTRY_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS experiments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS experiment_artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    experiment_id INTEGER NOT NULL,
                    role TEXT NOT NULL,
                    path TEXT NOT NULL,
                    artifact_family TEXT NOT NULL,
                    FOREIGN KEY (experiment_id) REFERENCES experiments(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS experiment_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    experiment_id INTEGER NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    metric_domain TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    FOREIGN KEY (experiment_id) REFERENCES experiments(id) ON DELETE CASCADE
                );
                """
            )
            connection.commit()

    def register_experiment(
        self,
        *,
        name: str,
        kind: str,
        domain: str,
        status: str = "completed",
        metadata: dict[str, Any] | None = None,
        metrics: dict[str, float] | None = None,
        artifacts: list[RegistryArtifact] | None = None,
    ) -> int:
        created_at = utc_now_iso()
        with closing(self._connect()) as connection:
            cursor = connection.execute(
                """
                INSERT INTO experiments (name, kind, domain, status, created_at, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, kind, domain, status, created_at, json.dumps(metadata or {}, sort_keys=True)),
            )
            if cursor.lastrowid is None:
                raise RuntimeError("failed to insert experiment row")
            experiment_id = int(cursor.lastrowid)
            if artifacts:
                connection.executemany(
                    """
                    INSERT INTO experiment_artifacts (experiment_id, role, path, artifact_family)
                    VALUES (?, ?, ?, ?)
                    """,
                    [
                        (experiment_id, artifact.role, artifact.path, artifact.artifact_family)
                        for artifact in artifacts
                    ],
                )
            if metrics:
                connection.executemany(
                    """
                    INSERT INTO experiment_metrics (experiment_id, metric_name, metric_value, metric_domain, context_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (experiment_id, metric_name, float(metric_value), domain, "{}")
                        for metric_name, metric_value in metrics.items()
                    ],
                )
            connection.commit()
        return experiment_id

    def list_experiments(self, *, limit: int = 20, kind: str | None = None) -> list[dict[str, Any]]:
        query = """
            SELECT id, name, kind, domain, status, created_at, metadata_json
            FROM experiments
        """
        parameters: list[Any] = []
        if kind:
            query += " WHERE kind = ?"
            parameters.append(kind)
        query += " ORDER BY id DESC LIMIT ?"
        parameters.append(int(limit))
        with closing(self._connect()) as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [self._row_to_experiment_summary(row) for row in rows]

    def get_experiment(self, experiment_id: int) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            experiment_row = connection.execute(
                """
                SELECT id, name, kind, domain, status, created_at, metadata_json
                FROM experiments
                WHERE id = ?
                """,
                (int(experiment_id),),
            ).fetchone()
            if experiment_row is None:
                raise ValueError(f"experiment not found: {experiment_id}")
            artifact_rows = connection.execute(
                """
                SELECT role, path, artifact_family
                FROM experiment_artifacts
                WHERE experiment_id = ?
                ORDER BY id ASC
                """,
                (int(experiment_id),),
            ).fetchall()
            metric_rows = connection.execute(
                """
                SELECT metric_name, metric_value, metric_domain, context_json
                FROM experiment_metrics
                WHERE experiment_id = ?
                ORDER BY metric_name ASC
                """,
                (int(experiment_id),),
            ).fetchall()
        summary = self._row_to_experiment_summary(experiment_row)
        summary["artifacts"] = [
            {
                "role": str(row["role"]),
                "path": str(row["path"]),
                "artifact_family": str(row["artifact_family"]),
            }
            for row in artifact_rows
        ]
        summary["metrics"] = {
            str(row["metric_name"]): float(row["metric_value"])
            for row in metric_rows
        }
        return summary

    def aggregate_metrics_by_domain(self, *, kind: str = "benchmark") -> dict[str, Any]:
        with closing(self._connect()) as connection:
            experiment_rows = connection.execute(
                """
                SELECT id, domain
                FROM experiments
                WHERE kind = ?
                ORDER BY id ASC
                """,
                (kind,),
            ).fetchall()
            metric_rows = connection.execute(
                """
                SELECT experiments.domain AS domain, experiment_metrics.metric_name AS metric_name,
                       experiment_metrics.metric_value AS metric_value
                FROM experiment_metrics
                JOIN experiments ON experiments.id = experiment_metrics.experiment_id
                WHERE experiments.kind = ?
                ORDER BY experiments.id ASC, experiment_metrics.metric_name ASC
                """,
                (kind,),
            ).fetchall()
        per_domain: dict[str, dict[str, list[float]]] = {}
        experiment_count: dict[str, int] = {}
        for row in experiment_rows:
            domain = str(row["domain"])
            experiment_count[domain] = experiment_count.get(domain, 0) + 1
            per_domain.setdefault(domain, {})
        for row in metric_rows:
            domain = str(row["domain"])
            metric_name = str(row["metric_name"])
            metric_value = float(row["metric_value"])
            per_domain.setdefault(domain, {}).setdefault(metric_name, []).append(metric_value)

        summary: dict[str, Any] = {}
        for domain, metric_map in sorted(per_domain.items()):
            summary[domain] = {
                "experiments": experiment_count.get(domain, 0),
                "metrics": {
                    metric_name: {
                        "count": len(values),
                        "avg": sum(values) / len(values),
                        "min": min(values),
                        "max": max(values),
                    }
                    for metric_name, values in sorted(metric_map.items())
                    if values
                },
            }
        return {
            "kind": kind,
            "registry": str(self.db_path),
            "domains": summary,
        }

    @staticmethod
    def _row_to_experiment_summary(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": int(row["id"]),
            "name": str(row["name"]),
            "kind": str(row["kind"]),
            "domain": str(row["domain"]),
            "status": str(row["status"]),
            "created_at": str(row["created_at"]),
            "metadata": json.loads(str(row["metadata_json"]) or "{}"),
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect Betta-Morpho research experiments stored in SQLite.")
    parser.add_argument("--db", default=str(DEFAULT_REGISTRY_PATH), help="Experiment registry SQLite path")
    subcommands = parser.add_subparsers(dest="command", required=True)

    list_cmd = subcommands.add_parser("list", help="List recent experiments")
    list_cmd.add_argument("--limit", type=int, default=20, help="Maximum rows to print")
    list_cmd.add_argument("--kind", default=None, help="Optional experiment kind filter")

    show_cmd = subcommands.add_parser("show", help="Show one experiment with metrics and artifacts")
    show_cmd.add_argument("--id", type=int, required=True, help="Experiment id")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    registry = ExperimentRegistry(args.db)
    if args.command == "list":
        items = registry.list_experiments(limit=args.limit, kind=args.kind)
        print(json.dumps(items, indent=2))
        return 0
    if args.command == "show":
        print(json.dumps(registry.get_experiment(args.id), indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
