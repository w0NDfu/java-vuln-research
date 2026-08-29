/** Work1 V11 direct CodeQL call edges around one callable source span. */
import java

string callableKind(Callable c) {
  c instanceof Constructor and result = "CONSTRUCTOR"
  or c instanceof Method and result = "METHOD"
}

string mappedCallableIdentity(Callable c) {
  result = callableKind(c) + "@" + c.getLocation().getFile().getRelativePath() + ":" +
    c.getLocation().getStartLine().toString() + ":" + c.getLocation().getStartColumn().toString()
}

predicate targetCallable(Callable c) {
  mappedCallableIdentity(c) = {{CODEQL_IDENTITY}}
}

string callableId(Callable c) {
  result = c.getDeclaringType().getQualifiedName() + "." + c.getName() + "/" +
    c.getNumberOfParameters().toString()
}

from Callable target, MethodCall call, Callable caller, Method callee, string edgeKind
where
  targetCallable(target) and
  call.getEnclosingCallable() = caller and
  call.getMethod() = callee and
  (
    callee = target and edgeKind = "CALLER"
    or caller = target and edgeKind = "CALLEE"
  )
select
  callableId(caller), callableId(callee), edgeKind,
  call.getLocation().getFile().getRelativePath(),
  call.getLocation().getStartLine(), call.getLocation().getEndLine(), callableId(caller)
