/** @name Work1 P0-B seed-independent effect candidates @kind table */
import java
import semmle.code.java.dataflow.DataFlow
import route_b.RouteBModels

from DataFlow::Node node, MethodCall call, string reason, string effectCategory,
  string evidenceKind, string confidence, string valueRole, int argumentIndex
where routeBEffectCandidate(node, call, reason, effectCategory, evidenceKind, confidence,
  valueRole, argumentIndex)
select reason, callEntity(call), callableIdentity(call.getEnclosingCallable()),
  callIdentity(call), valueRole, argumentIndex,
  node.asExpr().getLocation().getFile().getRelativePath(),
  node.asExpr().getLocation().getStartLine(), evidenceKind, confidence, effectCategory
