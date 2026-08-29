/** Work1 V11 neutral entity facts for one bounded source span. */
import java

predicate inTargetSpan(Element e) {
  e.getLocation().getFile().getRelativePath() = {{PATH}} and
  e.getLocation().getStartLine() <= {{END_LINE}} and
  e.getLocation().getEndLine() >= {{START_LINE}}
}

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
  or result = ""
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
  or result = ""
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
