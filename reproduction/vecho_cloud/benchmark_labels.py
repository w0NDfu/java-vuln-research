"""Resolve label-name discrepancies using explicit benchmark identifiers only."""


def select_labels(project, rows):
    exact = [r for r in rows if r["project_slug"] == project["project_slug"]]
    if exact:
        return exact, {"selection": "exact_project_slug", "label_project_slugs": [project["project_slug"]]}
    fix_commits = set(project["fix_commit_ids"].split(";")) - {""}
    matched = [r for r in rows
               if r["cve_id"] == project["cve_id"]
               and r["github_username"].casefold() == project["github_username"].casefold()
               and r["github_repository_name"].casefold() == project["github_repository_name"].casefold()
               and r["commit"] in fix_commits]
    return matched, {"selection": "cve_repository_and_fix_commit" if matched else "no_matching_labels",
                     "label_project_slugs": sorted({r["project_slug"] for r in matched}),
                     "matched_fix_commits": sorted({r["commit"] for r in matched})}
