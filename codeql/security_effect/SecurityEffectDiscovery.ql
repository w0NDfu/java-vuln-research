/**
 * @name MSA P0-A security effect discovery
 * @description Emits deterministic high-confidence security-effect primitives
 *              and one-hop wrappers whose parameter directly reaches a critical role.
 * @kind table
 */

import java

predicate isFilesystemEffect(MethodAccess call, string mechanism, int criticalIndex) {
  call.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
  call.getMethod().getName() = [
    "newInputStream", "newOutputStream", "newBufferedReader", "newBufferedWriter",
    "readAllBytes", "readAllLines", "readString", "write", "writeString", "copy", "move",
    "delete", "deleteIfExists", "createFile", "createDirectory", "createDirectories",
    "createTempFile", "createTempDirectory"
  ] and
  mechanism = "JAVA_NIO_FILES_" + call.getMethod().getName() and
  criticalIndex = 0
}

predicate isProcessEffect(MethodAccess call, string mechanism, int criticalIndex) {
  call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
  call.getMethod().getName() = "exec" and
  mechanism = "RUNTIME_EXEC" and
  criticalIndex = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
  call.getMethod().getName() = "start" and
  mechanism = "PROCESS_BUILDER_START" and
  criticalIndex = -1
}

predicate isRenderingEffect(MethodAccess call, string mechanism, int criticalIndex) {
  exists(MethodAccess getWriter |
    call.getQualifier() = getWriter and
    getWriter.getMethod().getName() = "getWriter" and
    (
      getWriter.getMethod().getDeclaringType().hasQualifiedName("javax.servlet", "ServletResponse")
      or getWriter.getMethod().getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletResponse")
      or getWriter.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse")
      or getWriter.getMethod().getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse")
    ) and
    call.getMethod().getName() = ["write", "print", "println", "printf", "append"] and
    mechanism = "SERVLET_RESPONSE_WRITER_" + call.getMethod().getName() and
    criticalIndex = 0
  )
}

predicate isDynamicEvaluationEffect(MethodAccess call, string mechanism, int criticalIndex) {
  (
    call.getMethod().getDeclaringType().hasQualifiedName("javax.script", "ScriptEngine")
    or call.getMethod().getDeclaringType().hasQualifiedName("javax.script", "AbstractScriptEngine")
  ) and
  call.getMethod().getName() = "eval" and
  mechanism = "SCRIPT_ENGINE_EVAL" and
  criticalIndex = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") and
  call.getMethod().getName() = "parseExpression" and
  mechanism = "SPRING_EXPRESSION_PARSE" and
  criticalIndex = 0
}

predicate isEffectCall(
  MethodAccess call, string effectType, string mechanism, int criticalIndex
) {
  isFilesystemEffect(call, mechanism, criticalIndex) and effectType = "FILESYSTEM_ACCESS"
  or
  isProcessEffect(call, mechanism, criticalIndex) and effectType = "PROCESS_EXECUTION"
  or
  isRenderingEffect(call, mechanism, criticalIndex) and effectType = "RENDERING"
  or
  isDynamicEvaluationEffect(call, mechanism, criticalIndex) and
  effectType = "DYNAMIC_EVALUATION"
}

string callEntity(MethodAccess call) {
  result = call.getEnclosingCallable().getDeclaringType().getQualifiedName() + "." +
    call.getEnclosingCallable().getName() + " -> " + call.getMethod().getQualifiedName()
}

string wrapperEntity(Method method, string effectType) {
  result = method.getDeclaringType().getQualifiedName() + "." + method.getName() +
    " PROJECT_SPECIFIC_" + effectType
}

from string effectType, string mechanism, string entity, string criticalRole,
  string evidenceKind, string file, int line, string source
where
  exists(MethodAccess call, int criticalIndex |
    isEffectCall(call, effectType, mechanism, criticalIndex) and
    entity = callEntity(call) and
    criticalRole =
      if criticalIndex = -1 then "receiver" else "arg" + criticalIndex.toString() and
    evidenceKind = "DANGEROUS_PRIMITIVE_CALL" and
    file = call.getLocation().getFile().getRelativePath() and
    line = call.getLocation().getStartLine() and
    source = "STATIC"
  )
  or
  exists(MethodAccess call, int criticalIndex, Method wrapper, Parameter p, VarAccess access |
    isEffectCall(call, effectType, mechanism, criticalIndex) and
    criticalIndex >= 0 and
    call.getEnclosingCallable() = wrapper and
    p.getCallable() = wrapper and
    access = p.getAnAccess() and
    call.getArgument(criticalIndex) = access and
    entity = wrapperEntity(wrapper, effectType) and
    criticalRole = "parameter:" + p.getName() and
    evidenceKind = "DIRECT_PARAMETER_EFFECT_WRAPPER" and
    file = call.getLocation().getFile().getRelativePath() and
    line = call.getLocation().getStartLine() and
    source = "STATIC_DERIVED"
  )
select effectType, mechanism, entity, criticalRole, evidenceKind, file, line, source

