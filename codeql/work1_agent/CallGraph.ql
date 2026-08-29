/** Work1 V11 direct CodeQL call edges around one callable source span. */
import java

predicate targetCallable(Callable c) {
  c.getLocation().getFile().getRelativePath() = {{PATH}} and
  c.getLocation().getStartLine() <= {{END_LINE}} and
  c.getLocation().getEndLine() >= {{START_LINE}}
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
