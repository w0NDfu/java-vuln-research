"""AST-backed Java declarations and explicit, ambiguity-preserving resolution."""
from __future__ import annotations

import re
from dataclasses import replace
from collections import defaultdict

from .entity import ProgramEntity, ProgramEntityKind

DECLARATIONS = {'class_declaration', 'interface_declaration', 'enum_declaration',
                'record_declaration', 'annotation_type_declaration'}
METHODS = {'method_declaration', 'constructor_declaration', 'compact_constructor_declaration'}


def compact(text):
    return re.sub(r'\s+', '', text)


class JavaSymbols:
    def __init__(self, index):
        from tree_sitter import Language, Parser
        import tree_sitter_java
        self.index = index
        self.parser = Parser(Language(tree_sitter_java.language()))
        self.methods, self.types, self.calls, self.parents = {}, {}, {}, {}
        self.parse_errors = []
        self.by_file = defaultdict(list)
        self.ranges = {}
        old = list(index.entities)
        for file in sorted({e.repository_relative_path for e in old if e.kind.value == 'FILE'}):
            data = (index.repository_root / file).read_bytes()
            tree = self.parser.parse(data)
            if tree.root_node.has_error:
                self.parse_errors.append(file)
            package_node = next((n for n in tree.root_node.named_children if n.type == 'package_declaration'), None)
            package = ''
            if package_node:
                package = package_node.text.decode().removeprefix('package').strip().rstrip(';').strip()
            self._visit(tree.root_node, file, package, None, None)
        self.entities = {**self.types, **self.methods}
        # The benchmark view replaces lexical declarations only. Legacy modes keep their original index.
        children = []
        for e in old:
            if e.kind.value in {'TYPE', 'METHOD', 'CONSTRUCTOR'}:
                continue
            if e.enclosing_callable:
                owners = self.at(e.repository_relative_path, e.start_line)
                if len(owners) == 1:
                    m = owners[0]
                    e = replace(e, enclosing_type=m.enclosing_type,
                                enclosing_callable=m.qualified_name + m.signature[len(m.simple_name):])
            children.append(e)
        index.entities = [*children, *self.types.values(), *self.methods.values()]

    def _visit(self, node, file, package, owner, method):
        is_anon = node.type == 'class_body' and node.parent is not None and node.parent.type in {'object_creation_expression', 'enum_constant'}
        if node.type in DECLARATIONS or is_anon:
            name_node = node.child_by_field_name('name')
            name = name_node.text.decode() if name_node else f'$anon@{node.start_point.row + 1}:{node.start_point.column + 1}'
            if method and not is_anon:
                name += f'$local@{node.start_point.row + 1}'
            qualified = '.'.join(p for p in (owner or package, name) if p)
            relations = []
            for child in node.named_children:
                if child.type in {'superclass', 'super_interfaces', 'extends_interfaces'}:
                    text = re.sub(r'^(extends|implements)\s+', '', child.text.decode()).strip()
                    relations.extend(x.strip() for x in text.split(','))
            if is_anon and node.parent.type == 'object_creation_expression':
                typ = node.parent.child_by_field_name('type')
                if typ: relations.append(typ.text.decode())
            entity = ProgramEntity.create(kind='TYPE', repository_relative_path=file,
                start_line=node.start_point.row + 1, end_line=node.end_point.row + 1,
                simple_name=name, qualified_name=qualified, enclosing_type=owner,
                signature=node.type + ' ' + name, type_text=' '.join(relations),
                provenance={'extractor': 'JAVA_TREE_SITTER_R13', 'anonymous': is_anon},
                identity_discriminator=node.start_byte)
            self.types[entity.entity_id] = entity
            self.parents[qualified] = relations
            owner, method = qualified, None
        if node.type in METHODS:
            name_node = node.child_by_field_name('name')
            if name_node is None: return
            name = name_node.text.decode()
            params = node.child_by_field_name('parameters')
            parameters = []
            if params:
                for p in params.named_children:
                    if p.type not in {'formal_parameter', 'spread_parameter', 'receiver_parameter'}: continue
                    typ = p.child_by_field_name('type')
                    if typ is None:
                        typ = next((x for x in p.named_children if x.type not in {'modifiers', 'variable_declarator', 'identifier'}), None)
                    text = compact(typ.text.decode()) if typ else '?'
                    if p.type == 'spread_parameter': text += '...'
                    dims = p.child_by_field_name('dimensions')
                    if dims: text += compact(dims.text.decode())
                    parameters.append(text)
            signature = name + '(' + ','.join(parameters) + ')'
            modifiers = next((x.text.decode().split() for x in node.named_children if x.type == 'modifiers'), [])
            typ = node.child_by_field_name('type')
            entity = ProgramEntity.create(kind='METHOD' if node.type == 'method_declaration' else 'CONSTRUCTOR',
                repository_relative_path=file, start_line=node.start_point.row + 1, end_line=node.end_point.row + 1,
                simple_name=name, qualified_name=(owner + '.' if owner else '') + name,
                enclosing_type=owner, signature=signature, type_text=typ.text.decode() if typ else owner,
                provenance={'extractor': 'JAVA_TREE_SITTER_R13', 'public': 'public' in modifiers,
                            'protected': 'protected' in modifiers, 'private': 'private' in modifiers,
                            'parameters': parameters, 'annotations': [x.text.decode() for x in node.named_children if x.type == 'modifiers']},
                identity_discriminator=name_node.start_byte)
            self.methods[entity.entity_id] = entity
            self.by_file[file].append(entity)
            self.ranges[entity.entity_id] = (node.start_point, node.end_point)
            self.calls[entity.entity_id] = []
            method = entity.entity_id
        if node.type in {'method_invocation', 'object_creation_expression'} and method:
            name = node.child_by_field_name('name') or node.child_by_field_name('type')
            receiver = node.child_by_field_name('object')
            args = node.child_by_field_name('arguments')
            arguments = args.named_children if args else []
            self.calls[method].append({'name': name.text.decode() if name else '',
                'receiver': receiver.text.decode() if receiver else '',
                'arguments': [x.text.decode()[:240] for x in arguments],
                'dynamic_arguments': sum(x.type not in {'string_literal', 'character_literal', 'decimal_integer_literal', 'true', 'false', 'null_literal'} for x in arguments),
                'line': node.start_point.row + 1, 'column': node.start_point.column + 1})
        for child in node.named_children:
            self._visit(child, file, package, owner, method)

    def at(self, file, line, column=None):
        hits = [m for m in self.by_file.get(file, []) if m.start_line <= line <= m.end_line]
        if column is not None:
            point = (line - 1, column - 1)
            hits = [m for m in hits if self.ranges[m.entity_id][0] <= point < self.ranges[m.entity_id][1]]
        # Retain innermost declarations; same-line siblings remain ambiguous without a column.
        return [m for m in hits if not any(self.ranges[m.entity_id][0] <= self.ranges[n.entity_id][0]
                    and self.ranges[n.entity_id][1] <= self.ranges[m.entity_id][1]
                    and self.ranges[n.entity_id] != self.ranges[m.entity_id] for n in hits)]

    @staticmethod
    def describe(m):
        return {'method_id': m.entity_id, 'entity_id': m.entity_id, 'file': m.repository_relative_path,
                'type': m.enclosing_type, 'name': m.qualified_name, 'signature': m.signature,
                'start_line': m.start_line, 'end_line': m.end_line}

    def resolve(self, query, *, file=None, line=None):
        if query in self.methods:
            hits = [self.methods[query]]
        elif file and type(line) is int:
            hits = self.at(file, line)
        else:
            query = compact(str(query)).replace('#', '.').replace('$', '.')
            name, sep, signature = query.partition('(')
            type_name, _, short = name.rpartition('.')
            short = short or name
            types = {m.enclosing_type for m in self.methods.values() if not type_name
                     or m.enclosing_type.replace('$', '.') == type_name
                     or m.enclosing_type.replace('$', '.').endswith('.' + type_name)}
            # Follow source-declared inheritance, preserving all ambiguous type bindings.
            inherited = set(types)
            pending = list(types)
            while pending:
                current = pending.pop()
                for parent in self.parents.get(current, []):
                    erased = re.sub(r'<.*>', '', parent).replace('$', '.')
                    for typ in self.parents:
                        if (typ == erased or typ.endswith('.' + erased)) and typ not in inherited:
                            inherited.add(typ); pending.append(typ)
            hits = [m for m in self.methods.values() if m.simple_name == short and m.enclosing_type in inherited
                    and (m.enclosing_type in types or not m.provenance.get('private'))]
            if sep:
                wanted = signature.rstrip(')')
                exact = [m for m in hits if compact(m.signature).partition('(')[2].rstrip(')') == wanted]
                if exact: hits = exact
                else:
                    def erase(s):
                        return re.sub(r'\b(?:[a-zA-Z_$][\w$]*\.)+', '', re.sub(r'<[^<>]*>', '', s))
                    hits = [m for m in hits if erase(compact(m.signature).partition('(')[2].rstrip(')')) == erase(wanted)]
            if type_name:
                direct_sigs = {m.signature for m in hits if m.enclosing_type in types}
                hits = [m for m in hits if m.enclosing_type in types or m.signature not in direct_sigs]
        if file: hits = [m for m in hits if m.repository_relative_path == file]
        return sorted(hits, key=lambda m: (m.repository_relative_path, m.start_line, m.signature))
