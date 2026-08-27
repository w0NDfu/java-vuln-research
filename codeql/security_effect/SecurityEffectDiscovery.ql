/**
 * @name MSA P0-A security effect discovery
 * @description Emits deterministic, generic SecurityEffect primitives and direct wrappers.
 * @kind table
 * @id w1-e1/security-effect-discovery
 */

import java
import security_effect.SecurityEffectModels

string wrapperEntity(Method method) {
  result = method.getDeclaringType().getQualifiedName() + "." + method.getName()
}

from string effectType, string mechanism, string entity, string criticalRole,
  string evidenceKind, string file, int line, string source, string primitiveRuleId,
  string calleeIdentity, string methodIdentity, string callIdentity, int argumentIndex,
  string anchorKind
where
  exists(MethodCall call, int criticalIndex |
    securityEffectCall(call, effectType, primitiveRuleId, mechanism, criticalIndex) and
    entity = seCallEntity(call) and
    seCriticalRole(criticalIndex, criticalRole) and
    evidenceKind = "DANGEROUS_PRIMITIVE_CALL" and
    file = call.getLocation().getFile().getRelativePath() and
    line = call.getLocation().getStartLine() and
    source = "STATIC" and
    calleeIdentity = seCalleeIdentity(call) and
    methodIdentity = seCallableIdentity(call.getEnclosingCallable()) and
    callIdentity = seCallIdentity(call) and
    argumentIndex = criticalIndex and
    seAnchorKind(criticalIndex, anchorKind)
  )
  or
  exists(MethodCall call, int criticalIndex, Method wrapper, Parameter p, VarAccess access |
    securityEffectCall(call, effectType, primitiveRuleId, mechanism, criticalIndex) and
    criticalIndex >= 0 and
    call.getEnclosingCallable() = wrapper and
    p.getCallable() = wrapper and
    access = p.getAnAccess() and
    call.getArgument(criticalIndex) = access and
    entity = wrapperEntity(wrapper) + " PROJECT_SPECIFIC_" + effectType and
    criticalRole = "parameter:" + p.getName() and
    evidenceKind = "DIRECT_PARAMETER_EFFECT_WRAPPER" and
    file = call.getLocation().getFile().getRelativePath() and
    line = call.getLocation().getStartLine() and
    source = "STATIC_DERIVED" and
    calleeIdentity = seCalleeIdentity(call) and
    methodIdentity = seCallableIdentity(wrapper) and
    callIdentity = seCallIdentity(call) and
    argumentIndex = p.getPosition() and
    anchorKind = "METHOD_PARAMETER"
  )
select effectType, mechanism, entity, criticalRole, evidenceKind, file, line, source,
  primitiveRuleId, calleeIdentity, methodIdentity, callIdentity, argumentIndex, anchorKind
