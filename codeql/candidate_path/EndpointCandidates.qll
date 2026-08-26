/** Shared W1-E1 endpoint predicates. They intentionally mirror frozen P0-A anchors. */
import java
import semmle.code.java.dataflow.TaintTracking

predicate isSpringInputParameter(Parameter p) {
  exists(Annotation a |
    a = p.getAnAnnotation() and
    (
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestHeader") or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "CookieValue") or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody") or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "ModelAttribute")
    )
  )
}

predicate isJaxRsInputParameter(Parameter p) {
  exists(Annotation a, string packageName |
    a = p.getAnAnnotation() and
    packageName = ["javax.ws.rs", "jakarta.ws.rs"] and
    (
      a.getType().hasQualifiedName(packageName, "QueryParam") or
      a.getType().hasQualifiedName(packageName, "PathParam") or
      a.getType().hasQualifiedName(packageName, "HeaderParam") or
      a.getType().hasQualifiedName(packageName, "CookieParam") or
      a.getType().hasQualifiedName(packageName, "FormParam") or
      a.getType().hasQualifiedName(packageName, "BeanParam")
    )
  )
}

predicate isServletInputCall(MethodCall call) {
  exists(Method target |
    target = call.getMethod() and
    (
      target.getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest") or
      target.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletRequest") or
      target.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") or
      target.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest")
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
  ] and
  criticalIndex = 0
}

predicate isProcessEffect(MethodCall call, int criticalIndex) {
  call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
  call.getMethod().getName() = "exec" and
  criticalIndex = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
  call.getMethod().getName() = "start" and
  criticalIndex = -1
}

predicate isRenderingEffect(MethodCall call, int criticalIndex) {
  exists(MethodCall getWriter |
    call.getQualifier() = getWriter and
    getWriter.getMethod().getName() = "getWriter" and
    (
      getWriter.getMethod().getDeclaringType().hasQualifiedName("javax.servlet", "ServletResponse") or
      getWriter.getMethod().getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletResponse") or
      getWriter.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletResponse") or
      getWriter.getMethod().getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletResponse")
    ) and
    call.getMethod().getName() = ["write", "print", "println", "printf", "append"] and
    criticalIndex = 0
  )
}

predicate isDynamicEvaluationEffect(MethodCall call, int criticalIndex) {
  (
    call.getMethod().getDeclaringType().hasQualifiedName("javax.script", "ScriptEngine") or
    call.getMethod().getDeclaringType().hasQualifiedName("javax.script", "AbstractScriptEngine")
  ) and
  call.getMethod().getName() = "eval" and criticalIndex = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName("org.springframework.expression", "ExpressionParser") and
  call.getMethod().getName() = "parseExpression" and criticalIndex = 0
}

predicate isEffectCall(MethodCall call, int criticalIndex) {
  isFilesystemEffect(call, criticalIndex) or
  isProcessEffect(call, criticalIndex) or
  isRenderingEffect(call, criticalIndex) or
  isDynamicEvaluationEffect(call, criticalIndex)
}

predicate externalInputNode(DataFlow::Node node, string file, int line) {
  exists(Parameter p |
    (isSpringInputParameter(p) or isJaxRsInputParameter(p)) and
    node.asParameter() = p and
    file = p.getLocation().getFile().getRelativePath() and
    line = p.getLocation().getStartLine()
  )
  or
  exists(MethodCall call |
    isServletInputCall(call) and
    node.asExpr() = call and
    file = call.getLocation().getFile().getRelativePath() and
    line = call.getLocation().getStartLine()
  )
}

predicate securityEffectNode(DataFlow::Node node, string file, int line) {
  exists(MethodCall call, int criticalIndex |
    isEffectCall(call, criticalIndex) and
    (
      criticalIndex >= 0 and node.asExpr() = call.getArgument(criticalIndex)
      or
      criticalIndex = -1 and node.asExpr() = call.getQualifier()
    ) and
    file = call.getLocation().getFile().getRelativePath() and
    line = call.getLocation().getStartLine()
  )
}

predicate inputCallable(DataFlow::Node node, Callable callable) {
  exists(Parameter p |
    node.asParameter() = p and callable = p.getCallable()
  )
  or
  exists(Expr expr |
    node.asExpr() = expr and callable = expr.getEnclosingCallable()
  )
}

predicate effectCallable(DataFlow::Node node, Callable callable) {
  exists(Expr expr |
    node.asExpr() = expr and callable = expr.getEnclosingCallable()
  )
}
