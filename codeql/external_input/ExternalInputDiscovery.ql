/**
 * @name MSA P0-A external input discovery
 * @description Emits deterministic high-confidence external-input anchors and
 *              one-hop return wrappers without using project ground truth.
 * @kind table
 */

import java

predicate isSpringInputParameter(Parameter p, string mechanism) {
  exists(Annotation a |
    a = p.getAnAnnotation() and
    (
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestParam") and
      mechanism = "SPRING_REQUEST_PARAM"
      or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "PathVariable") and
      mechanism = "SPRING_PATH_VARIABLE"
      or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestHeader") and
      mechanism = "SPRING_REQUEST_HEADER"
      or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "CookieValue") and
      mechanism = "SPRING_COOKIE_VALUE"
      or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestBody") and
      mechanism = "SPRING_REQUEST_BODY"
      or
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation", "ModelAttribute") and
      mechanism = "SPRING_MODEL_ATTRIBUTE"
    )
  )
}

predicate isJaxRsInputParameter(Parameter p, string mechanism) {
  exists(Annotation a, string packageName |
    a = p.getAnAnnotation() and
    packageName = ["javax.ws.rs", "jakarta.ws.rs"] and
    (
      a.getType().hasQualifiedName(packageName, "QueryParam") and mechanism = "JAXRS_QUERY_PARAM"
      or
      a.getType().hasQualifiedName(packageName, "PathParam") and mechanism = "JAXRS_PATH_PARAM"
      or
      a.getType().hasQualifiedName(packageName, "HeaderParam") and mechanism = "JAXRS_HEADER_PARAM"
      or
      a.getType().hasQualifiedName(packageName, "CookieParam") and mechanism = "JAXRS_COOKIE_PARAM"
      or
      a.getType().hasQualifiedName(packageName, "FormParam") and mechanism = "JAXRS_FORM_PARAM"
      or
      a.getType().hasQualifiedName(packageName, "BeanParam") and mechanism = "JAXRS_BEAN_PARAM"
    )
  )
}

predicate isServletInputCall(MethodCall call, string mechanism) {
  exists(Method target |
    target = call.getMethod() and
    (
      target.getDeclaringType().hasQualifiedName("javax.servlet", "ServletRequest")
      or target.getDeclaringType().hasQualifiedName("jakarta.servlet", "ServletRequest")
      or target.getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")
      or target.getDeclaringType().hasQualifiedName("jakarta.servlet.http", "HttpServletRequest")
    ) and
    (
      target.getName() = "getParameter" and mechanism = "SERVLET_PARAMETER"
      or target.getName() = "getParameterValues" and mechanism = "SERVLET_PARAMETER_VALUES"
      or target.getName() = "getParameterMap" and mechanism = "SERVLET_PARAMETER_MAP"
      or target.getName() = "getHeader" and mechanism = "SERVLET_HEADER"
      or target.getName() = "getHeaders" and mechanism = "SERVLET_HEADERS"
      or target.getName() = "getCookies" and mechanism = "SERVLET_COOKIES"
      or target.getName() = "getInputStream" and mechanism = "SERVLET_INPUT_STREAM"
      or target.getName() = "getReader" and mechanism = "SERVLET_READER"
      or target.getName() = "getQueryString" and mechanism = "SERVLET_QUERY_STRING"
      or target.getName() = "getPathInfo" and mechanism = "SERVLET_PATH_INFO"
    )
  )
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

from string mechanism, string entity, string evidenceKind, string file, int line, string source
where
  exists(Parameter p |
    (isSpringInputParameter(p, mechanism) or isJaxRsInputParameter(p, mechanism)) and
    entity = parameterEntity(p) and
    evidenceKind = "ANNOTATED_PARAMETER" and
    file = p.getLocation().getFile().getRelativePath() and
    line = p.getLocation().getStartLine() and
    source = "STATIC"
  )
  or
  exists(MethodCall call |
    isServletInputCall(call, mechanism) and
    entity = callEntity(call) and
    evidenceKind = "SERVLET_ACCESSOR_CALL" and
    file = call.getLocation().getFile().getRelativePath() and
    line = call.getLocation().getStartLine() and
    source = "STATIC"
  )
  or
  exists(Method wrapper, ReturnStmt ret, MethodCall call |
    ret.getEnclosingCallable() = wrapper and
    ret.getExpr() = call and
    isServletInputCall(call, mechanism) and
    entity = returnEntity(wrapper) and
    evidenceKind = "DIRECT_RETURN_WRAPPER" and
    file = ret.getLocation().getFile().getRelativePath() and
    line = ret.getLocation().getStartLine() and
    source = "STATIC_DERIVED"
  )
  or
  exists(Method wrapper, Parameter p, ReturnStmt ret, VarAccess access |
    p.getCallable() = wrapper and
    ret.getEnclosingCallable() = wrapper and
    access = p.getAnAccess() and
    ret.getExpr() = access and
    (isSpringInputParameter(p, mechanism) or isJaxRsInputParameter(p, mechanism)) and
    entity = returnEntity(wrapper) and
    evidenceKind = "DIRECT_PARAMETER_RETURN_WRAPPER" and
    file = ret.getLocation().getFile().getRelativePath() and
    line = ret.getLocation().getStartLine() and
    source = "STATIC_DERIVED"
  )
select mechanism, entity, evidenceKind, file, line, source
