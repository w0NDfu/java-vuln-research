/**
 * @name Work1 P0-B base-graph connected paths
 * @description Uses only CodeQL base taint/data/call semantics after structural gating.
 * @kind table
 */
import java
import semmle.code.java.dataflow.DataFlow
import route_b.RouteBModels

from DataFlow::Node input, Parameter p, string inputReason, string inputEvidence,
  string inputConfidence, DataFlow::Node effect, MethodCall call, string effectReason,
  string effectCategory, string effectEvidence, string effectConfidence,
  string valueRole, int argumentIndex, int distance, string gateReason
where
  routeBInputCandidate(input, p, inputReason, inputEvidence, inputConfidence) and
  routeBEffectCandidate(effect, call, effectReason, effectCategory, effectEvidence,
    effectConfidence, valueRole, argumentIndex) and
  routeBPairGate(input, effect, distance, gateReason) and
  RouteBFlow::flow(input, effect)
select parameterEntity(p), p.getLocation().getFile().getRelativePath(),
  p.getLocation().getStartLine(), inputReason, callEntity(call),
  effect.asExpr().getLocation().getFile().getRelativePath(),
  effect.asExpr().getLocation().getStartLine(), effectReason, gateReason, distance
