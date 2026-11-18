"""Bounded, source-located Java, mapper and view references for the A1 experiment."""
from __future__ import annotations

from collections import defaultdict
import hashlib
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
import re
from xml.parsers import expat

from .benchmark import digest, source_safe


RESOURCE_SUFFIXES = {'.xml', '.ftl', '.html', '.htm', '.jsp', '.js', '.mjs', '.css'}
MAX_FILE_BYTES = 512 * 1024
MAX_MAPPER_FILES = 256
MAX_WINDOWS = 16
MAX_PACKAGE_BYTES = 36_000
MAX_WINDOW_LINES = 120
MAX_WINDOW_BYTES = 9_000
MAX_RELATIONS = 40


def local_path(root, file):
    parts = PurePosixPath(file)
    if parts.is_absolute() or not parts.parts or '..' in parts.parts or '\\' in file:
        return None
    path = root.joinpath(*parts.parts)
    if path.resolve() != path or not path.is_file():
        return None
    return path


def resource_identity(file, file_sha256):
    return 'resource-' + digest([file, file_sha256])[:24]


def children(node, kinds):
    return [child for child in node.named_children if child.type in kinds]


def descendants(node, *, stop=()):
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        if current.type not in stop:
            stack.extend(reversed(current.named_children))


def text(node):
    return node.text.decode() if node is not None else ''


def string_literal(node):
    value = text(node)
    if node is not None and node.type == 'string_literal' and re.fullmatch(r'"[^"\\\n]*"', value):
        return value[1:-1]
    return None


class ViewScripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.references = []

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            sources = [value for name, value in attrs if name == 'src']
            if sources:
                first = self.getpos()[0]
                self.references.append((first, first + self.get_starttag_text().count('\n'),
                                        sources[0] if len(sources) == 1 else None))


def mapper_document(raw):
    """Return exact top-level MyBatis declaration spans with no external entity reads."""
    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.ExternalEntityRefHandler = lambda *_: 0
    stack, entries = [], []
    namespace = None

    def reject_entity(*_):
        raise ValueError('XML entity declarations are outside the supported subset.')

    def start(tag, attrs):
        nonlocal namespace
        if not stack and tag == 'mapper':
            namespace = attrs.get('namespace')
        if len(stack) == 1:
            entry = {'tag': tag, 'id': attrs.get('id'), 'first': parser.CurrentLineNumber,
                     'refs': [(v.strip(),parser.CurrentLineNumber)
                              for v in attrs.get('resultMap','').split(',') if v.strip()]}
            entries.append(entry)
        if len(stack) >= 2 and tag == 'include' and attrs.get('refid'):
            entries[-1]['refs'].append((attrs['refid'],parser.CurrentLineNumber))
        stack.append(tag)

    def end(_):
        stack.pop()
        if len(stack) == 1:
            entries[-1]['last'] = parser.CurrentLineNumber

    parser.EntityDeclHandler = reject_entity
    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.Parse(raw, True)
    return namespace, entries


class ResourceReferences:
    def __init__(self, root, parser):
        self.root = Path(root).resolve()
        self.parser = parser
        self.java = {}
        self.mappers = {}
        self.files = {}
        self.windows = {}
        self.views = {}
        self.stats = dict(file_reads=0,file_cache_hits=0,window_reads=0,window_cache_hits=0)

    def file(self, name):
        if name in self.files:
            self.stats['file_cache_hits'] += 1
            return self.files[name]
        path = local_path(self.root, name)
        if path is None or path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError('Unavailable or oversized source file.')
        raw = path.read_bytes()
        self.stats['file_reads'] += 1
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError('Source file exceeded the bound during read.')
        material = raw, raw.decode('utf-8').splitlines(), hashlib.sha256(raw).hexdigest()
        self.files[name] = material
        return material

    def mapper_index(self, base):
        if base not in self.mappers:
            records = defaultdict(list)
            folder = self.root / base
            if folder.resolve() != folder:
                raise ValueError('Resource root is a link.')
            files = []
            for path in folder.rglob('*.xml'):
                files.append(path)
                if len(files) > MAX_MAPPER_FILES:
                    raise ValueError('Mapper discovery file bound reached.')
            for path in sorted(files):
                name = path.relative_to(self.root).as_posix()
                try:
                    namespace, entries = mapper_document(self.file(name)[0])
                except (ValueError, OSError, expat.ExpatError):
                    continue
                if namespace:
                    for entry in entries:
                        if entry['id']:
                            records[f"{namespace}.{entry['id']}"].append((name, entry))
            self.mappers[base] = records
        return self.mappers[base]

    def build(self, java_proofs, *, methods, window_limit=MAX_WINDOWS, exposed=()):
        windows, prior, relations = {}, {}, []
        reads, hits, truncations = [], [], {}
        initial_counts = dict(self.stats)
        exposed = set(exposed)
        total_bytes = 0
        window_limit = min(window_limit, MAX_WINDOWS)

        def window(file, first=1, last=None):
            nonlocal total_bytes
            _, lines, file_hash = self.file(file)
            requested_end = len(lines) if last is None else last
            if not 1 <= first <= requested_end <= len(lines):
                return None
            key = file, file_hash, first, requested_end
            item = self.windows.get(key)
            if item is not None:
                identity = item['evidence_id']
                if item['end_line'] < requested_end:
                    truncations[key] = {'file':file,'requested':[first,requested_end],
                                        'returned':[first,item['end_line']]}
                self.stats['window_cache_hits'] += 1
                hits.append(identity)
                if identity in exposed:
                    prior[identity] = item
                    return item
                if identity in windows:
                    return windows[identity]
                size = len(item['source'].encode())
                if len(windows) >= MAX_WINDOWS or size + total_bytes > MAX_PACKAGE_BYTES:
                    return None
                windows[identity] = item
                total_bytes += size
                return item
            size, end = 0, first - 1
            for i in range(first, min(requested_end, first+MAX_WINDOW_LINES-1)+1):
                size += len(lines[i-1].encode()) + 12
                if size > MAX_WINDOW_BYTES:
                    break
                end = i
            if end < first:
                return None
            actual = file, file_hash, first, end
            if actual in self.windows:
                self.windows[key] = self.windows[actual]
                return window(file,first,last)
            if len(reads) >= window_limit or len(windows) >= MAX_WINDOWS or size + total_bytes > MAX_PACKAGE_BYTES:
                return None
            numbered = [{'line':n,'text':lines[n-1]} for n in range(first,end+1)]
            resource_id = resource_identity(file,file_hash)
            content_hash = digest(numbered)
            item = {'evidence_id':'rsrc-' + digest([resource_id,first,end,content_hash])[:24],
                    'resource_id':resource_id,'file':file,'file_sha256':file_hash,
                    'start_line':first,'end_line':end,
                    'source':source_safe('\n'.join(f"{r['line']:>6} | {r['text']}" for r in numbered)),
                    'content_sha256':content_hash,
                    'unknown_ranges': ([[1,first-1]] if first>1 else []) +
                                      ([[end+1,len(lines)]] if end<len(lines) else [])}
            self.windows[key] = self.windows[actual] = item
            if end < requested_end:
                truncations[key] = {'file':file,'requested':[first,requested_end],'returned':[first,end]}
            identity = item['evidence_id']
            self.stats['window_reads'] += 1
            reads.append(identity)
            windows[identity] = item
            total_bytes += len(item['source'].encode())
            return item

        def relation(kind, origin, line, target=None, *, reason=None, anchor=None):
            replace = None
            if len(relations) >= MAX_RELATIONS and target and target['evidence_id'] not in exposed:
                replace = next((i for i,r in enumerate(relations)
                                if r.get('to_evidence_id') in exposed),None)
            if len(relations) < MAX_RELATIONS or replace is not None:
                row = {'kind': kind, 'from_file': origin, 'from_line': line}
                if anchor:
                    row.update(anchor)
                if target:
                    row.update(status='RESOLVED', to_file=target['file'], to_evidence_id=target['evidence_id'],
                               scope='STATIC_REFERENCE')
                else:
                    row.update(status='UNKNOWN', reason=reason or 'Missing or outside evidence bounds.')
                if replace is not None:
                    relations.pop(replace)
                relations.append(row)

        def mapper(index, key, origin, line, kind, visited):
            matches = [item for item in index.get(key, ()) if kind != 'JAVA_MAPPER_CALL'
                       or item[1]['tag'] in {'select','insert','update','delete'}]
            if key in visited:
                return
            visited.add(key)
            if len(matches) != 1:
                relation(kind, origin, line, reason='Mapper binding absent or ambiguous.')
                return
            file, entry = matches[0]
            item = window(file, entry['first'], entry['last'])
            relation(kind, origin, line, item)
            if not item:
                return
            namespace = key.rsplit('.', 1)[0]
            for ref, reference_line in entry['refs']:
                mapper(index, ref if '.' in ref else f'{namespace}.{ref}', file, reference_line,
                       'MAPPER_DECLARATION_REFERENCE', visited)

        def view(base, origin, line, literal, anchor):
            if not re.fullmatch(r'[\w.-]+(?:/[\w.-]+)*', literal) or '..' in PurePosixPath(literal).parts:
                relation('CONTROLLER_VIEW', origin, line, reason='Unsupported view name.', anchor=anchor)
                return
            names = [f'{base}/templates/{literal}{ext}' for ext in ('', '.ftl', '.html', '.jsp')]
            matches = [f for f in names if PurePosixPath(f).suffix in RESOURCE_SUFFIXES and local_path(self.root, f)]
            if len(matches) != 1:
                relation('CONTROLLER_VIEW', origin, line, reason='View target absent or ambiguous.', anchor=anchor)
                return
            file = matches[0]
            _, lines, _ = self.file(file)
            if file not in self.views:
                parser = ViewScripts()
                template = re.sub(r'<#--.*?-->',lambda m:'\n'*m[0].count('\n'),
                                  '\n'.join(lines),flags=re.DOTALL)
                parser.feed(template)
                self.views[file] = parser.references
            references = self.views[file]
            if not references:
                relation('CONTROLLER_VIEW', origin, line, window(file), anchor=anchor)
            for first, last, src in references[:MAX_RELATIONS]:
                rendered = next((w for w in (*windows.values(),*prior.values()) if w['file']==file and
                                 w['start_line']<=first<=last<=w['end_line']),None)
                if not rendered:
                    rendered = window(file, max(1,first-2), min(len(lines),last+6))
                relation('CONTROLLER_VIEW', origin, line, rendered, anchor=anchor)
                if not rendered:
                    continue
                if src:
                    src = src.removeprefix('${request.contextPath}').removeprefix('${pageContext.request.contextPath}')
                if not src or not re.fullmatch(r'/?[\w.-]+(?:/[\w.-]+)*', src) or '..' in PurePosixPath(src).parts:
                    relation('SCRIPT_SRC', file, first, reason='Dynamic or external script source.')
                    continue
                if src.startswith('/'):
                    url = src[1:]
                    roots = [f'{base}/{folder}/{url}' for folder in ('static','public','META-INF/resources')]
                    roots.append(f'{base}/{url}')
                else:
                    roots = [f'{PurePosixPath(file).parent}/{src}']
                targets = [f for f in dict.fromkeys(PurePosixPath(p).as_posix() for p in roots)
                           if PurePosixPath(f).suffix in {'.js','.mjs'}
                           and local_path(self.root, f)]
                target = window(targets[0]) if len(targets)==1 else None
                relation('SCRIPT_SRC', file, first, target)
                if target:
                    # A minified script can exhaust a byte window well before
                    # the line limit. Supply one bounded adjacent continuation;
                    # no token-name search or inferred runtime binding is used.
                    _, script_lines, _ = self.file(target['file'])
                    if target['end_line'] < len(script_lines):
                        continuation = window(target['file'], target['end_line']+1)
                        relation('SCRIPT_CONTINUATION', target['file'],
                                 target['end_line'], continuation)
                    relation('SCRIPT_RUNTIME_BINDINGS', target['file'], target['start_line'],
                             reason='Runtime calls, values and DOM behavior require independent evidence.')

        visited_views, visited_mappers = set(), set()
        for proof in java_proofs:
            origin = proof['file']
            declaration = methods.get(proof.get('method_id'))
            if len(windows) >= MAX_WINDOWS:
                break
            if not origin.endswith('.java') or '/src/main/java/' not in '/'+origin:
                continue
            if (declaration is None or declaration.repository_relative_path != origin or
                    not declaration.start_line <= proof['start_line'] <= proof['end_line'] <= declaration.end_line):
                relation('PROJECT_REFERENCE',origin,proof['start_line'],reason='No exact Java declaration.')
                continue
            before, _ = ('/'+origin).rsplit('/src/main/java/',1)
            base = (before.lstrip('/')+'/' if before else '')+'src/main/resources'
            try:
                if origin not in self.java:
                    self.java[origin] = self.parser.parse(self.file(origin)[0])
                tree = self.java[origin]
                if tree.root_node.has_error:
                    raise ValueError('Java syntax tree incomplete.')
                imports = {}
                package = ''
                for node in tree.root_node.named_children:
                    val = text(node)
                    if node.type=='package_declaration':
                        package = val.removeprefix('package').strip().rstrip(';').strip()
                    if node.type=='import_declaration':
                        name = val.removeprefix('import').strip().rstrip(';').strip()
                        if re.fullmatch(r'[\w.]+',name):
                            imports[name.rsplit('.',1)[-1]] = name
                for owner in descendants(tree.root_node):
                    if owner.type not in {'class_declaration','record_declaration'}:
                        continue
                    body = owner.child_by_field_name('body')
                    owner_methods = children(body, {'method_declaration','constructor_declaration'})
                    focus = [m for m in owner_methods if m.start_point.row+1==declaration.start_line
                             and m.end_point.row+1==declaration.end_line and
                             text(m.child_by_field_name('name'))==declaration.simple_name]
                    if len(focus) != 1:
                        continue
                    fields = {}
                    for field in children(body, {'field_declaration'}):
                        typ = text(field.child_by_field_name('type'))
                        if not re.fullmatch(r'[\w.]+',typ):
                            continue
                        for decl in children(field, {'variable_declarator'}):
                            fields[text(decl.child_by_field_name('name'))] = imports.get(
                                typ, typ if '.' in typ or not package else f'{package}.{typ}')
                    member = focus[0]
                    blocked_names = {text(n.child_by_field_name('name')) for n in descendants(member)
                                     if n.type in {'formal_parameter','spread_parameter','variable_declarator',
                                                   'enhanced_for_statement','catch_formal_parameter'}}
                    for node in descendants(member, stop={'class_body','lambda_expression'}):
                        if node.type != 'method_invocation' or not (
                                proof['start_line']<=node.start_point.row+1<=proof['end_line']):
                            continue
                        recv = text(node.child_by_field_name('object'))
                        field = recv.removeprefix('this.')
                        if field not in fields or (recv==field and field in blocked_names):
                            continue
                        name = text(node.child_by_field_name('name'))
                        index = self.mapper_index(base)
                        key = f'{fields[field]}.{name}'
                        if any(k.rsplit('.',1)[0]==fields[field] for k in index):
                            mapper(index, key, origin, node.start_point.row+1, 'JAVA_MAPPER_CALL', visited_mappers)
                    annotation = text(next(iter(children(owner, {'modifiers'})), None))
                    if re.search(r'@(?:[\w.]+\.)?ResponseBody\b',annotation):
                        continue
                    if not (imports.get('Controller')=='org.springframework.stereotype.Controller'
                            and re.search(r'@Controller\b',annotation) or
                            '@org.springframework.stereotype.Controller' in annotation):
                        continue
                    for m in [member, *(x for x in owner_methods if x != member)]:
                        mods = text(next(iter(children(m, {'modifiers'})), None))
                        if not re.search(r'@(?:[\w.]+\.)?(?:Request|Get|Post|Put|Delete|Patch)Mapping\b',mods):
                            continue
                        if re.search(r'@(?:[\w.]+\.)?ResponseBody\b',mods):
                            continue
                        for n in descendants(m, stop={'class_body','lambda_expression'}):
                            if n.type != 'return_statement':
                                continue
                            value = string_literal(next(iter(n.named_children),None))
                            identity = origin, n.start_point.row+1, value
                            if identity in visited_views:
                                continue
                            visited_views.add(identity)
                            anchor = {'origin_scope':'CURRENT_METHOD' if m==member else 'SAME_CONTROLLER_VIEW_METHOD',
                                      'view_return_end_line':n.end_point.row+1}
                            if value is not None:
                                anchor['view_return'] = source_safe(text(n))[:512]
                            if value is None:
                                relation('CONTROLLER_VIEW', origin, identity[1],
                                         reason='Dynamic view name.',anchor=anchor)
                            else:
                                view(base, origin, identity[1], value, anchor)
            except (ValueError, OSError, UnicodeError) as exc:
                relation('PROJECT_REFERENCE', origin, proof['start_line'],
                         reason=f'Reference unavailable ({type(exc).__name__}).')
        if not relations and java_proofs:
            relations.append({'kind':'PROJECT_REFERENCE','status':'UNKNOWN',
                              'reason':'No reference in the supported static subset was resolved.'})
        return {'source_evidence':list(windows.values()),'previous_evidence':list(prior.values()),
                'relations':relations,'window_reads':reads,'window_cache_hits':hits,
                'truncations':list(truncations.values()),
                'read_counts':{key:value-initial_counts[key] for key,value in self.stats.items()}}
