/** Shared W1-E1 endpoint-to-value adapter. No new source/effect semantics. */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

predicate isSpringInputParameter(Parameter p) {
  exists(Annotation a |
    a = p.getAnAnnotation() and
    a.getType().hasQualifiedName("org.springframework.web.bind.annotation",
      ["RequestParam", "PathVariable", "RequestHeader", "CookieValue", "RequestBody", "ModelAttribute"])
  )
}

predicate isJaxRsInputParameter(Parameter p) {
  exists(Annotation a, string packageName |
    a = p.getAnAnnotation() and packageName = ["javax.ws.rs", "jakarta.ws.rs"] and
    a.getType().hasQualifiedName(packageName,
      ["QueryParam", "PathParam", "HeaderParam", "CookieParam", "FormParam", "BeanParam"])
  )
}

predicate isServletInputCall(MethodCall call) {
  exists(Method target |
    target = call.getMethod() and
    target.getDeclaringType().hasQualifiedName(
      ["javax.servlet", "jakarta.servlet", "javax.servlet.http", "jakarta.servlet.http"],
      ["ServletRequest", "HttpServletRequest"]
    ) and
    target.getName() = [
      "getParameter", "getParameterValues", "getParameterMap", "getHeader", "getHeaders",
      "getCookies", "getInputStream", "getReader", "getQueryString", "getPathInfo"
    ]
  )
}

predicate isFilesystemEffect(MethodCall call, int criticalIndex) {
  call.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
  call.getMethod().getName() = [
    "newInputStream", "newOutputStream", "newBufferedReader", "newBufferedWriter",
    "readAllBytes", "readAllLines", "readString", "write", "writeString", "copy", "move",
    "delete", "deleteIfExists", "createFile", "createDirectory", "createDirectories",
    "createTempFile", "createTempDirectory"
  ] and criticalIndex = 0
}

predicate isProcessEffect(MethodCall call, int criticalIndex) {
  call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
  call.getMethod().getName() = "exec" and criticalIndex = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
  call.getMethod().getName() = "start" and criticalIndex = -1
}

predicate isRenderingEffect(MethodCall call, int criticalIndex) {
  exists(MethodCall getWriter |
    call.getQualifier() = getWriter and getWriter.getMethod().getName() = "getWriter" and
    getWriter.getMethod().getDeclaringType().hasQualifiedName(
      ["javax.servlet", "jakarta.servlet", "javax.servlet.http", "jakarta.servlet.http"],
      ["ServletResponse", "HttpServletResponse"]
    ) and
    call.getMethod().getName() = ["write", "print", "println", "printf", "append"] and
    criticalIndex = 0
  )
}

predicate isDynamicEvaluationEffect(MethodCall call, int criticalIndex) {
  call.getMethod().getDeclaringType().hasQualifiedName(
    "javax.script", ["ScriptEngine", "AbstractScriptEngine"]
  ) and call.getMethod().getName() = "eval" and criticalIndex = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName(
    "org.springframework.expression", "ExpressionParser"
  ) and call.getMethod().getName() = "parseExpression" and criticalIndex = 0
}

predicate isEffectCall(MethodCall call, int criticalIndex) {
  isFilesystemEffect(call, criticalIndex) or isProcessEffect(call, criticalIndex) or
  isRenderingEffect(call, criticalIndex) or isDynamicEvaluationEffect(call, criticalIndex)
}

string callableIdentity(Callable callable) {
  result = callable.getDeclaringType().getQualifiedName() + "." + callable.getName() +
    "/" + callable.getNumberOfParameters().toString()
}

string parameterEntity(Parameter p) {
  result = p.getCallable().getDeclaringType().getQualifiedName() + "." +
    p.getCallable().getName() + " parameter " + p.getName()
}

string callEntity(MethodCall call) {
  result = call.getEnclosingCallable().getDeclaringType().getQualifiedName() + "." +
    call.getEnclosingCallable().getName() + " -> " + call.getMethod().getQualifiedName()
}

string returnEntity(Method method) {
  result = method.getDeclaringType().getQualifiedName() + "." + method.getName() + " return"
}

string wrapperEffectEntity(Method method, string effectType) {
  result = method.getDeclaringType().getQualifiedName() + "." + method.getName() +
    " PROJECT_SPECIFIC_" + effectType
}

string callIdentity(MethodCall call) {
  result = call.getMethod().getQualifiedName() + "@" +
    call.getLocation().getFile().getRelativePath() + ":" +
    call.getLocation().getStartLine().toString()
}

predicate effectTypeFor(MethodCall call, string effectType, int criticalIndex) {
  isFilesystemEffect(call, criticalIndex) and effectType = "FILESYSTEM_ACCESS"
  or isProcessEffect(call, criticalIndex) and effectType = "PROCESS_EXECUTION"
  or isRenderingEffect(call, criticalIndex) and effectType = "RENDERING"
  or isDynamicEvaluationEffect(call, criticalIndex) and effectType = "DYNAMIC_EVALUATION"
}

predicate externalInputAnalysisAnchor(
  DataFlow::Node node, string candidateEntity, string candidateFile, int candidateLine,
  string anchorKind, string valueRole, string methodIdentity, string mappedCallIdentity,
  int argumentIndex, string anchorFile, int anchorLine, string mappingReason
) {
  exists(Parameter p |
    (isSpringInputParameter(p) or isJaxRsInputParameter(p)) and node.asParameter() = p and
    candidateEntity = parameterEntity(p) and
    candidateFile = p.getLocation().getFile().getRelativePath() and
    candidateLine = p.getLocation().getStartLine() and
    anchorKind = "PARAMETER" and valueRole = "PARAMETER" and
    methodIdentity = callableIdentity(p.getCallable()) and mappedCallIdentity = "" and
    argumentIndex = p.getPosition() and anchorFile = candidateFile and anchorLine = candidateLine and
    mappingReason = "ANNOTATED_PARAMETER_VALUE"
  )
  or
  exists(MethodCall call |
    isServletInputCall(call) and node.asExpr() = call and candidateEntity = callEntity(call) and
    candidateFile = call.getLocation().getFile().getRelativePath() and
    candidateLine = call.getLocation().getStartLine() and
    anchorKind = "CALL_RESULT" and valueRole = "CALL_RESULT" and
    methodIdentity = callableIdentity(call.getEnclosingCallable()) and
    mappedCallIdentity = callIdentity(call) and argumentIndex = -1 and
    anchorFile = candidateFile and anchorLine = candidateLine and
    mappingReason = "SERVLET_CALL_RESULT_VALUE"
  )
  or
  exists(Method wrapper, ReturnStmt ret, MethodCall call |
    ret.getEnclosingCallable() = wrapper and ret.getExpr() = call and isServletInputCall(call) and
    node.asExpr() = ret.getExpr() and candidateEntity = returnEntity(wrapper) and
    candidateFile = ret.getLocation().getFile().getRelativePath() and
    candidateLine = ret.getLocation().getStartLine() and
    anchorKind = "METHOD_RETURN" and valueRole = "METHOD_RETURN" and
    methodIdentity = callableIdentity(wrapper) and mappedCallIdentity = callIdentity(call) and
    argumentIndex = -1 and anchorFile = ret.getExpr().getLocation().getFile().getRelativePath() and
    anchorLine = ret.getExpr().getLocation().getStartLine() and mappingReason = "DIRECT_RETURN_VALUE"
  )
  or
  exists(Method wrapper, Parameter p, ReturnStmt ret, VarAccess access |
    p.getCallable() = wrapper and ret.getEnclosingCallable() = wrapper and access = p.getAnAccess() and
    ret.getExpr() = access and (isSpringInputParameter(p) or isJaxRsInputParameter(p)) and
    node.asExpr() = ret.getExpr() and candidateEntity = returnEntity(wrapper) and
    candidateFile = ret.getLocation().getFile().getRelativePath() and
    candidateLine = ret.getLocation().getStartLine() and
    anchorKind = "METHOD_RETURN" and valueRole = "METHOD_RETURN" and
    methodIdentity = callableIdentity(wrapper) and mappedCallIdentity = "" and argumentIndex = -1 and
    anchorFile = ret.getExpr().getLocation().getFile().getRelativePath() and
    anchorLine = ret.getExpr().getLocation().getStartLine() and
    mappingReason = "DIRECT_PARAMETER_RETURN_VALUE"
  )
}

predicate securityEffectAnalysisAnchor(
  DataFlow::Node node, string candidateEntity, string candidateFile, int candidateLine,
  string anchorKind, string valueRole, string methodIdentity, string mappedCallIdentity,
  int argumentIndex, string anchorFile, int anchorLine, string mappingReason
) {
  exists(MethodCall call, int criticalIndex |
    isEffectCall(call, criticalIndex) and
    (
      criticalIndex >= 0 and node.asExpr() = call.getArgument(criticalIndex) and
      anchorKind = "CALL_ARGUMENT" and valueRole = "CALL_ARGUMENT" and argumentIndex = criticalIndex
      or
      criticalIndex = -1 and node.asExpr() = call.getQualifier() and
      anchorKind = "RECEIVER" and valueRole = "RECEIVER" and argumentIndex = -1
    ) and
    candidateEntity = callEntity(call) and
    candidateFile = call.getLocation().getFile().getRelativePath() and
    candidateLine = call.getLocation().getStartLine() and
    methodIdentity = callableIdentity(call.getEnclosingCallable()) and
    mappedCallIdentity = callIdentity(call) and
    anchorFile = node.asExpr().getLocation().getFile().getRelativePath() and
    anchorLine = node.asExpr().getLocation().getStartLine() and
    mappingReason = "SECURITY_CRITICAL_CALL_VALUE"
  )
  or
  exists(MethodCall call, int criticalIndex, string effectType, Method wrapper, Parameter p, VarAccess access |
    effectTypeFor(call, effectType, criticalIndex) and criticalIndex >= 0 and
    call.getEnclosingCallable() = wrapper and p.getCallable() = wrapper and
    access = p.getAnAccess() and call.getArgument(criticalIndex) = access and node.asParameter() = p and
    candidateEntity = wrapperEffectEntity(wrapper, effectType) and
    candidateFile = call.getLocation().getFile().getRelativePath() and
    candidateLine = call.getLocation().getStartLine() and
    anchorKind = "METHOD_PARAMETER" and valueRole = "METHOD_PARAMETER" and
    methodIdentity = callableIdentity(wrapper) and mappedCallIdentity = callIdentity(call) and
    argumentIndex = p.getPosition() and anchorFile = p.getLocation().getFile().getRelativePath() and
    anchorLine = p.getLocation().getStartLine() and
    mappingReason = "DIRECT_EFFECT_WRAPPER_PARAMETER_VALUE"
  )
}

predicate analysisNodeInfo(
  DataFlow::Node node, string nodeKind, string nodeEntity, string nodeFile, int nodeLine,
  string nodeMethodIdentity
) {
  exists(Parameter p |
    node.asParameter() = p and nodeKind = "PARAMETER" and nodeEntity = parameterEntity(p) and
    nodeFile = p.getLocation().getFile().getRelativePath() and
    nodeLine = p.getLocation().getStartLine() and nodeMethodIdentity = callableIdentity(p.getCallable())
  )
  or
  exists(MethodCall call |
    node.asExpr() = call and nodeKind = "CALL_RESULT" and nodeEntity = callEntity(call) and
    nodeFile = call.getLocation().getFile().getRelativePath() and
    nodeLine = call.getLocation().getStartLine() and
    nodeMethodIdentity = callableIdentity(call.getEnclosingCallable())
  )
  or
  exists(MethodCall call, Expr argument |
    argument = call.getAnArgument() and node.asExpr() = argument and nodeKind = "CALL_ARGUMENT" and
    nodeEntity = callEntity(call) + " argument" and
    nodeFile = argument.getLocation().getFile().getRelativePath() and
    nodeLine = argument.getLocation().getStartLine() and
    nodeMethodIdentity = callableIdentity(call.getEnclosingCallable())
  )
  or
  exists(ReturnStmt ret |
    node.asExpr() = ret.getExpr() and nodeKind = "METHOD_RETURN" and
    nodeEntity = callableIdentity(ret.getEnclosingCallable()) + " return value" and
    nodeFile = ret.getExpr().getLocation().getFile().getRelativePath() and
    nodeLine = ret.getExpr().getLocation().getStartLine() and
    nodeMethodIdentity = callableIdentity(ret.getEnclosingCallable())
  )
}

predicate analysisNodeCallable(DataFlow::Node node, Callable callable) {
  exists(Parameter p | node.asParameter() = p and callable = p.getCallable())
  or exists(Expr expr | node.asExpr() = expr and callable = expr.getEnclosingCallable())
}

module W1E1ConnectedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(string ce, string cf, int cl, string ak, string vr, string mi, string ci,
      int ai, string af, int al, string mr |
      externalInputAnalysisAnchor(source, ce, cf, cl, ak, vr, mi, ci, ai, af, al, mr))
  }
  predicate isSink(DataFlow::Node sink) {
    exists(string ce, string cf, int cl, string ak, string vr, string mi, string ci,
      int ai, string af, int al, string mr |
      securityEffectAnalysisAnchor(sink, ce, cf, cl, ak, vr, mi, ci, ai, af, al, mr))
  }
}
module W1E1ConnectedFlow = TaintTracking::Global<W1E1ConnectedConfig>;

module W1E1ForwardConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(string ce, string cf, int cl, string ak, string vr, string mi, string ci,
      int ai, string af, int al, string mr |
      externalInputAnalysisAnchor(source, ce, cf, cl, ak, vr, mi, ci, ai, af, al, mr))
  }
  predicate isSink(DataFlow::Node sink) {
    exists(string nk, string ne, string nf, int nl, string nm |
      analysisNodeInfo(sink, nk, ne, nf, nl, nm))
  }
}
module W1E1ForwardFlow = TaintTracking::Global<W1E1ForwardConfig>;

module W1E1BackwardConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(string nk, string ne, string nf, int nl, string nm |
      analysisNodeInfo(source, nk, ne, nf, nl, nm))
  }
  predicate isSink(DataFlow::Node sink) {
    exists(string ce, string cf, int cl, string ak, string vr, string mi, string ci,
      int ai, string af, int al, string mr |
      securityEffectAnalysisAnchor(sink, ce, cf, cl, ak, vr, mi, ci, ai, af, al, mr))
  }
}
module W1E1BackwardFlow = TaintTracking::Global<W1E1BackwardConfig>;

predicate directlyCalls(Callable caller, Callable callee) {
  exists(MethodCall call | call.getEnclosingCallable() = caller and call.getMethod() = callee)
}

predicate sameReceiverVariable(DataFlow::Node left, DataFlow::Node right) {
  exists(MethodCall leftCall, MethodCall rightCall, VarAccess leftReceiver, VarAccess rightReceiver |
    left.asExpr() = leftCall and right.asExpr() = rightCall and
    leftCall.getQualifier() = leftReceiver and rightCall.getQualifier() = rightReceiver and
    leftReceiver.getVariable() = rightReceiver.getVariable())
}

predicate sameField(DataFlow::Node left, DataFlow::Node right) {
  exists(FieldAccess leftAccess, FieldAccess rightAccess |
    left.asExpr() = leftAccess and right.asExpr() = rightAccess and
    leftAccess.getField() = rightAccess.getField())
}

predicate structuralRelation(DataFlow::Node left, DataFlow::Node right, int distance, string reason) {
  exists(Callable leftCallable, Callable rightCallable |
    analysisNodeCallable(left, leftCallable) and analysisNodeCallable(right, rightCallable) and
    (
      leftCallable = rightCallable and distance = 0 and reason = "SAME_METHOD"
      or
      leftCallable != rightCallable and
      (directlyCalls(leftCallable, rightCallable) or directlyCalls(rightCallable, leftCallable)) and
      distance = 1 and reason = "CALL_ADJACENT"
      or
      leftCallable != rightCallable and sameReceiverVariable(left, right) and
      distance = 1 and reason = "SAME_RECEIVER"
      or
      leftCallable != rightCallable and sameField(left, right) and
      distance = 1 and reason = "FIELD_RELATED"
      or
      exists(Callable middle |
        (directlyCalls(leftCallable, middle) and directlyCalls(middle, rightCallable) or
         directlyCalls(rightCallable, middle) and directlyCalls(middle, leftCallable)) and
        distance = 2 and reason = "NEAR_CALL_REGION"))
  )
}
