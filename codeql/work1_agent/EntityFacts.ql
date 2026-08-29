/** Work1 V11 neutral entity facts for up to eleven bounded source spans. */
import java

string entityKind(Element e) {
  exists(RefType t | e = t and result = "TYPE")
  or exists(Constructor c | e = c and result = "CONSTRUCTOR")
  or exists(Method m | e = m and result = "METHOD")
  or exists(Parameter p | e = p and result = "PARAMETER")
  or exists(Field f | e = f and result = "FIELD")
  or exists(MethodCall c | e = c and result = "CALL")
  or exists(Annotation a | e = a and result = "ANNOTATION")
  or exists(ReturnStmt r | e = r and result = "RETURN")
  or exists(LocalVariableDecl l | e = l and result = "LOCAL")
}

predicate target(string path, int startLine, int endLine, string expectedKind) {
  path = {{PATH_0}} and startLine = {{START_LINE_0}} and endLine = {{END_LINE_0}} and expectedKind = {{KIND_0}}
  or path = {{PATH_1}} and startLine = {{START_LINE_1}} and endLine = {{END_LINE_1}} and expectedKind = {{KIND_1}}
  or path = {{PATH_2}} and startLine = {{START_LINE_2}} and endLine = {{END_LINE_2}} and expectedKind = {{KIND_2}}
  or path = {{PATH_3}} and startLine = {{START_LINE_3}} and endLine = {{END_LINE_3}} and expectedKind = {{KIND_3}}
  or path = {{PATH_4}} and startLine = {{START_LINE_4}} and endLine = {{END_LINE_4}} and expectedKind = {{KIND_4}}
  or path = {{PATH_5}} and startLine = {{START_LINE_5}} and endLine = {{END_LINE_5}} and expectedKind = {{KIND_5}}
  or path = {{PATH_6}} and startLine = {{START_LINE_6}} and endLine = {{END_LINE_6}} and expectedKind = {{KIND_6}}
  or path = {{PATH_7}} and startLine = {{START_LINE_7}} and endLine = {{END_LINE_7}} and expectedKind = {{KIND_7}}
  or path = {{PATH_8}} and startLine = {{START_LINE_8}} and endLine = {{END_LINE_8}} and expectedKind = {{KIND_8}}
  or path = {{PATH_9}} and startLine = {{START_LINE_9}} and endLine = {{END_LINE_9}} and expectedKind = {{KIND_9}}
  or path = {{PATH_10}} and startLine = {{START_LINE_10}} and endLine = {{END_LINE_10}} and expectedKind = {{KIND_10}}
}

predicate inTargetSpan(Element e) {
  exists(string path, int startLine, int endLine, string expectedKind |
    target(path, startLine, endLine, expectedKind) and
    e.getLocation().getFile().getRelativePath() = path and
    e.getLocation().getStartLine() <= endLine and
    e.getLocation().getEndLine() >= startLine and
    entityKind(e) = expectedKind
  )
}

string qualifiedIdentity(Element e) {
  exists(RefType t | e = t and result = t.getQualifiedName())
  or exists(Callable c |
    e = c and result = c.getDeclaringType().getQualifiedName() + "." + c.getName())
  or exists(Field f |
    e = f and result = f.getDeclaringType().getQualifiedName() + "." + f.getName())
  or exists(Parameter p |
    e = p and result = p.getCallable().getDeclaringType().getQualifiedName() + "." +
      p.getCallable().getName() + " parameter " + p.getPosition().toString())
  or exists(MethodCall c |
    e = c and result = c.getEnclosingCallable().getDeclaringType().getQualifiedName() + "." +
      c.getEnclosingCallable().getName() + " -> " + c.getMethod().getQualifiedName())
  or exists(Annotation a | e = a and result = "@" + a.getType().getQualifiedName())
  or exists(ReturnStmt r |
    e = r and result = r.getEnclosingCallable().getDeclaringType().getQualifiedName() + "." +
      r.getEnclosingCallable().getName() + " return")
  or exists(LocalVariableDecl l |
    e = l and result = l.getEnclosingCallable().getDeclaringType().getQualifiedName() + "." +
      l.getEnclosingCallable().getName() + " local " + l.getName())
}

string entitySignature(Element e) {
  exists(Callable c | e = c and result = c.getName() + "/" + c.getNumberOfParameters().toString())
  or exists(MethodCall c |
    e = c and result = c.getMethod().getName() + "/" + c.getMethod().getNumberOfParameters().toString())
  or not e instanceof Callable and not e instanceof MethodCall and result = ""
}

string declaringType(Element e) {
  exists(RefType t | e = t and result = t.getQualifiedName())
  or exists(Callable c | e = c and result = c.getDeclaringType().getQualifiedName())
  or exists(Field f | e = f and result = f.getDeclaringType().getQualifiedName())
  or exists(Parameter p | e = p and result = p.getCallable().getDeclaringType().getQualifiedName())
  or exists(Expr x | e = x and result = x.getEnclosingCallable().getDeclaringType().getQualifiedName())
  or exists(Stmt s | e = s and result = s.getEnclosingCallable().getDeclaringType().getQualifiedName())
  or not e instanceof RefType and not e instanceof Callable and not e instanceof Field and
    not e instanceof Parameter and not e instanceof Expr and not e instanceof Stmt and result = ""
}

string enclosingCallable(Element e) {
  exists(Callable c | e = c and result = c.getDeclaringType().getQualifiedName() + "." + c.getName())
  or exists(Parameter p |
    e = p and result = p.getCallable().getDeclaringType().getQualifiedName() + "." + p.getCallable().getName())
  or exists(Expr x |
    e = x and result = x.getEnclosingCallable().getDeclaringType().getQualifiedName() + "." +
      x.getEnclosingCallable().getName())
  or exists(Stmt s |
    e = s and result = s.getEnclosingCallable().getDeclaringType().getQualifiedName() + "." +
      s.getEnclosingCallable().getName())
  or not e instanceof Callable and not e instanceof Parameter and not e instanceof Expr and
    not e instanceof Stmt and result = ""
}

from Element e, string kind
where inTargetSpan(e) and kind = entityKind(e)
select
  kind + "@" + e.getLocation().getFile().getRelativePath() + ":" +
    e.getLocation().getStartLine().toString() + ":" + e.getLocation().getStartColumn().toString(),
  kind,
  e.getLocation().getFile().getRelativePath(),
  e.getLocation().getStartLine(),
  e.getLocation().getEndLine(),
  qualifiedIdentity(e),
  entitySignature(e),
  declaringType(e),
  enclosingCallable(e)
