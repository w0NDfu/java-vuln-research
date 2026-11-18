"""SARIF preservation and deterministic source-location mapping for Discovery."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit, urljoin


def canonical_sarif(payload, source_root):
    if payload.get('version') != '2.1.0' or not isinstance(payload.get('runs'), list):
        raise ValueError('Expected SARIF 2.1.0 runs.')
    output = []
    for run_index, run in enumerate(payload['runs']):
        if any(i.get('executionSuccessful') is False for i in run.get('invocations', [])):
            raise ValueError('SARIF execution failed.')
        driver = run['tool']['driver']
        rules = {r['id']: r for r in driver.get('rules', [])}
        for extension in run.get('tool', {}).get('extensions', []):
            rules.update({r['id']: r for r in extension.get('rules', [])})
        def uri(artifact, seen=()):
            artifact = dict(artifact)
            if 'uri' not in artifact and 'index' in artifact:
                artifact = {**run['artifacts'][artifact['index']]['location'], **artifact}
            value = artifact['uri']
            base = artifact.get('uriBaseId')
            if base and base in run.get('originalUriBaseIds', {}):
                if base in seen:
                    raise ValueError('Cyclic SARIF URI base.')
                value = urljoin(uri(run['originalUriBaseIds'][base], (*seen, base)), value)
            return value
        def location(loc):
            from .repository.entity import normalise_repository_path
            physical = loc['physicalLocation']
            value = unquote(uri(physical['artifactLocation'])).replace('\\', '/')
            if value.startswith('file:'):
                parsed = urlsplit(value)
                if parsed.netloc not in ('', 'localhost'):
                    raise ValueError('Remote SARIF URI.')
                value = parsed.path
            root = str(source_root).replace('\\', '/').rstrip('/')
            if re.match(r'^/[A-Za-z]:/', value): value = value[1:]
            if value.startswith(root + '/'):
                value = value[len(root) + 1:]
            value = normalise_repository_path(value)
            region = physical['region']
            line = region['startLine']
            if type(line) is not int or line < 1:
                raise ValueError('Invalid SARIF line.')
            return {'file_path': value, 'line_number': line,
                    'column': region.get('startColumn'), 'end_line': region.get('endLine', line),
                    'end_column': region.get('endColumn'), 'description': loc.get('message', {}).get('text', '')}
        for index, result in enumerate(run.get('results', [])):
            rule_id = result.get('ruleId')
            if not rule_id and type(result.get('ruleIndex')) is int:
                rule_id = driver['rules'][result['ruleIndex']]['id']
            rule = rules.get(rule_id, {})
            tags = [*rule.get('properties', {}).get('tags', []), *result.get('properties', {}).get('tags', [])]
            cwes = sorted({'CWE-' + str(int(m)) for tag in tags for m in re.findall(r'(?:cwe[-/])0*(\d+)', tag, re.I)})
            paths = []
            for flow in result.get('codeFlows', []):
                for thread in flow.get('threadFlows', []):
                    points = []
                    for step in thread.get('locations', []):
                        if 'index' in step:
                            step = {**run['threadFlowLocations'][step['index']], **step}
                        if 'physicalLocation' in step.get('location', {}):
                            points.append(location(step['location']))
                    if points: paths.append(points)
            positions = [location(x) for x in result.get('locations', []) if 'physicalLocation' in x]
            if not positions and not paths:
                raise ValueError('Native result lacks source locations.')
            affected = {}
            for point in positions:
                affected.setdefault(point['file_path'], set()).add(point['line_number'])
            output.append({'source_scanner': 'CodeQL', 'rule_id': rule_id, 'cwe': cwes[0] if len(cwes) == 1 else '',
                           'cwes': cwes, 'description': result.get('message', {}).get('text', ''),
                           'category': rule_id, 'affected_files': [{'file_path': f, 'line_numbers': sorted(lines)} for f, lines in sorted(affected.items())],
                           'locations': positions, 'tainted_data_flow': paths,
                           'metadata': {'run': run_index, 'result': index, 'tags': tags,
                                        'path_evidence': 'reported_path' if paths else 'location_only'}})
    return {'vulnerabilities': output, 'native_status': 'complete'}


def map_alerts(payload, symbols):
    """Keep ambiguous/unknown locations as such, never guess by basename or name."""
    alerts = []
    for raw in payload['vulnerabilities']:
        points = [*raw.get('locations', []), *[p for flow in raw.get('tainted_data_flow', []) for p in flow]]
        mapped = []
        for point in points:
            candidates = symbols.at(point['file_path'], point['line_number'], point.get('column'))
            mapped.append({**point, 'method_ids': [m.entity_id for m in candidates],
                           'mapping': 'unique' if len(candidates) == 1 else 'ambiguous' if candidates else 'unmapped'})
        identity = hashlib.sha256(json.dumps([raw.get('rule_id'), raw.get('cwes'), points], sort_keys=True).encode()).hexdigest()[:24]
        alerts.append({**raw, 'native_id': 'native-' + identity, 'mapped_locations': mapped})
    locations = [p for a in alerts for p in a['mapped_locations']]
    unique = sum(p['mapping'] == 'unique' for p in locations)
    return alerts, {'alerts': len(alerts), 'locations': len(locations), 'uniquely_mapped': unique,
                    'mapping_rate': unique / len(locations) if locations else None,
                    'alerts_with_unique_method': sum(any(p['mapping'] == 'unique' for p in a['mapped_locations']) for a in alerts)}


SINKS = {
    'CWE-22': {'File', 'FileInputStream', 'FileOutputStream', 'RandomAccessFile', 'readAllBytes', 'newInputStream', 'newOutputStream', 'getResource', 'getResourceAsStream', 'resolve', 'child', 'stat', 'readToString', 'unzip', 'extract'},
    'CWE-78': {'exec', 'start', 'command', 'launch', 'cmds', 'ProcessBuilder'},
    'CWE-79': {'write', 'print', 'println', 'append', 'getWriter', 'sendError'},
    'CWE-94': {'eval', 'evaluate', 'parseScript', 'GroovyShell', 'ScriptEngine', 'compile', 'interpret', 'executeScript'},
}
SOURCES = {'getParameter', 'getParameterValues', 'getQuery', 'getQueryString', 'getRequestURI',
           'getInputStream', 'getReader', 'getHeader', 'getPathInfo', 'getSubmittedFileName', 'getString', 'bindJSON'}


def method_signals(method, symbols, alerts, related=False):
    calls = symbols.calls.get(method.entity_id, [])
    native = [a for a in alerts if any(method.entity_id in p['method_ids'] and p['mapping'] == 'unique' for p in a['mapped_locations'])]
    sources = [c for c in calls if c['name'] in SOURCES]
    binding = bool(method.provenance.get('public') and method.provenance.get('parameters'))
    scores, sinks = {}, {}
    for cwe, names in SINKS.items():
        matched = [c for c in calls if c['name'].split('.')[-1] in names]
        # ProcessBuilder.start is useful; unrelated zero-argument start is only a weak hint.
        if cwe == 'CWE-78':
            matched = [c for c in matched if c['name'] != 'start' or 'process' in c['receiver'].lower() or 'builder' in c['receiver'].lower()]
        sinks[cwe] = matched
        native_count = sum(cwe in a.get('cwes', [a.get('cwe')]) for a in native)
        scores[cwe] = 24 * min(native_count, 2) + 8 * min(len(matched), 3) + 3 * min(sum(c['dynamic_arguments'] > 0 for c in matched), 2)
        scores[cwe] += 4 * min(len(sources), 2) + 2 * binding + 2 * bool(related)
    return {'scores': scores, 'dangerous_calls': sinks, 'source_calls': sources,
            'framework_or_public_binding': binding, 'native_ids': [a['native_id'] for a in native],
            'origins': [name for name, present in [('CODEQL_NATIVE', native), ('AST_DANGEROUS_CALL', any(sinks.values())),
                         ('SOURCE_OR_BINDING', sources or binding), ('PROGRAM_RELATION', related)] if present]}


def merge_leads(rows, proposals, cwes, limit=48):
    """One method exploration covers all CWEs; select diverse concrete evidence first."""
    merged = {}
    for row in rows.values():
        cwe = max(cwes, key=lambda c: row['scores'][c])
        merged[row['method_id']] = {'method_id': row['method_id'], 'cwe': cwe,
            'reason': 'Multi-source Discovery: ' + ', '.join(row.get('origins', [])),
            'origins': list(row.get('origins', [])), 'score': row['scores'][cwe], 'file': row['file']}
    for lead in proposals:
        if not isinstance(lead, dict) or lead.get('method_id') not in merged or lead.get('cwe') not in cwes:
            continue
        row = merged[lead['method_id']]
        first_agent_proposal = 'AGENT_DISCOVERY' not in row['origins']
        row['origins'] = sorted(set([*row['origins'], 'AGENT_DISCOVERY']))
        row['reason'] = str(lead.get('reason', ''))[:800]
        row['score'] += 3 * first_agent_proposal
        if rows[lead['method_id']]['scores'][lead['cwe']] >= row['score'] - 3:
            row['cwe'] = lead['cwe']
    result, used_cwe, used_file = [], {}, {}
    while merged and len(result) < limit:
        def priority(row):
            return (-(row['score'] - 7 * used_cwe.get(row['cwe'], 0) - 2 * used_file.get(row['file'], 0)), row['file'], row['method_id'])
        best = min(merged.values(), key=priority)
        merged.pop(best['method_id'])
        result.append(best)
        used_cwe[best['cwe']] = used_cwe.get(best['cwe'], 0) + 1
        used_file[best['file']] = used_file.get(best['file'], 0) + 1
    return result
