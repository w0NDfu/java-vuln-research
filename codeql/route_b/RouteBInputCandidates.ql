/** @name Work1 P0-B seed-independent input candidates @kind table */
import java
import semmle.code.java.dataflow.DataFlow
import route_b.RouteBModels

from DataFlow::Node node, Parameter p, string reason, string evidenceKind, string confidence
where routeBInputCandidate(node, p, reason, evidenceKind, confidence)
select reason, parameterEntity(p), callableIdentity(p.getCallable()), "", "PARAMETER",
  p.getPosition(), p.getLocation().getFile().getRelativePath(),
  p.getLocation().getStartLine(), evidenceKind, confidence, "REQUEST_OR_CALLBACK_SEMANTICS"
