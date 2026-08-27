/**
 * @name SecurityEffect generic taxonomy contract test
 * @description Emits direct primitive and AnalysisAnchor metadata for the isolated toy fixture.
 * @kind table
 */

import java
import semmle.code.java.dataflow.DataFlow
import security_effect.SecurityEffectModels
import candidate_path.EndpointCandidates

from MethodCall call, string effectType, string primitiveRuleId, string mechanism,
  int criticalIndex, string criticalRole, DataFlow::Node node, string candidateEntity,
  string candidateFile, int candidateLine, string anchorKind, string valueRole,
  string methodIdentity, string mappedCallIdentity, int argumentIndex, string anchorFile,
  int anchorLine, string mappingReason
where
  securityEffectCall(call, effectType, primitiveRuleId, mechanism, criticalIndex) and
  seCriticalRole(criticalIndex, criticalRole) and
  securityEffectAnalysisAnchor(
    node, candidateEntity, candidateFile, candidateLine, anchorKind, valueRole,
    methodIdentity, mappedCallIdentity, argumentIndex, anchorFile, anchorLine, mappingReason
  ) and
  candidateEntity = seCallEntity(call) and
  mappedCallIdentity = seCallIdentity(call) and
  argumentIndex = criticalIndex and
  mappingReason = "SECURITY_CRITICAL_CALL_VALUE"
select call.getEnclosingCallable().getName(),
  call.getMethod().getDeclaringType().getQualifiedName(), call.getMethod().getName(),
  effectType, primitiveRuleId, criticalIndex, criticalRole, anchorKind, valueRole,
  mappingReason
