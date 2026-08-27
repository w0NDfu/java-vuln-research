/** Shared, project-agnostic SecurityEffect taxonomy for Route A. */
import java

predicate filesystemEffect(MethodCall call, string rule, string mechanism, int index) {
  call.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
  call.getMethod().getName() = [
    "newInputStream", "newOutputStream", "newBufferedReader", "newBufferedWriter",
    "readAllBytes", "readAllLines", "readString", "write", "writeString", "copy", "move",
    "delete", "deleteIfExists", "createFile", "createDirectory", "createDirectories",
    "createTempFile", "createTempDirectory"
  ] and rule = "JDK_NIO_FILES_PATH_ARG0" and
  mechanism = "JAVA_NIO_FILES_" + call.getMethod().getName() and index = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class") and
  call.getMethod().getName() = ["getResource", "getResourceAsStream"] and
  rule = "JDK_CLASS_RESOURCE_NAME_ARG0" and
  mechanism = "JAVA_CLASS_" + call.getMethod().getName() and index = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ClassLoader") and
  call.getMethod().getName() = ["getResource", "getResourceAsStream", "getResources"] and
  rule = "JDK_CLASSLOADER_RESOURCE_NAME_ARG0" and
  mechanism = "JAVA_CLASSLOADER_" + call.getMethod().getName() and index = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") and
  call.getMethod().getName() = [
    "canRead", "canWrite", "exists", "isDirectory", "isFile", "list", "listFiles",
    "delete", "mkdir", "mkdirs", "createNewFile"
  ] and rule = "JDK_FILE_PATH_RECEIVER" and
  mechanism = "JAVA_IO_FILE_" + call.getMethod().getName() and index = -1
}

predicate processEffect(MethodCall call, string rule, string mechanism, int index) {
  call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
  call.getMethod().getName() = "exec" and rule = "JDK_RUNTIME_EXEC_ARG0" and
  mechanism = "RUNTIME_EXEC" and index = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and
  call.getMethod().getName() = "start" and rule = "JDK_PROCESS_BUILDER_START_RECEIVER" and
  mechanism = "PROCESS_BUILDER_START" and index = -1
}

predicate renderingEffect(MethodCall call, string rule, string mechanism, int index) {
  exists(MethodCall accessor |
    call.getQualifier() = accessor and
    accessor.getMethod().getName() = ["getWriter", "getOutputStream"] and
    accessor.getMethod().getDeclaringType().hasQualifiedName(
      ["javax.servlet", "jakarta.servlet", "javax.servlet.http", "jakarta.servlet.http"],
      ["ServletResponse", "HttpServletResponse"]
    ) and
    call.getMethod().getName() = ["write", "print", "println", "printf", "append"] and
    rule = "SERVLET_RESPONSE_BODY_ARG0" and
    mechanism = "SERVLET_RESPONSE_" + accessor.getMethod().getName() + "_" +
      call.getMethod().getName() and index = 0
  )
  or
  call.getMethod().getDeclaringType().hasQualifiedName(
    ["javax.servlet.http", "jakarta.servlet.http"], "HttpServletResponse"
  ) and call.getMethod().getName() = "sendRedirect" and
  rule = "SERVLET_RESPONSE_REDIRECT_ARG0" and
  mechanism = "SERVLET_RESPONSE_SEND_REDIRECT" and index = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName(
    ["javax.servlet.http", "jakarta.servlet.http"], "HttpServletResponse"
  ) and call.getMethod().getName() = ["setHeader", "addHeader"] and
  rule = "SERVLET_RESPONSE_HEADER_VALUE_ARG1" and
  mechanism = "SERVLET_RESPONSE_" + call.getMethod().getName() and index = 1
}

predicate dynamicEvaluationEffect(MethodCall call, string rule, string mechanism, int index) {
  call.getMethod().getDeclaringType().hasQualifiedName(
    "javax.script", ["ScriptEngine", "AbstractScriptEngine"]
  ) and call.getMethod().getName() = "eval" and
  rule = "JDK_SCRIPT_ENGINE_EVAL_ARG0" and mechanism = "SCRIPT_ENGINE_EVAL" and index = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName(
    "org.springframework.expression", "ExpressionParser"
  ) and call.getMethod().getName() = "parseExpression" and
  rule = "SPRING_EXPRESSION_PARSE_ARG0" and mechanism = "SPRING_EXPRESSION_PARSE" and index = 0
}

predicate regexEvaluationEffect(MethodCall call, string rule, string mechanism, int index) {
  call.getMethod().getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
  call.getMethod().getName() = "compile" and rule = "JDK_PATTERN_COMPILE_REGEX_ARG0" and
  mechanism = "JAVA_PATTERN_COMPILE" and index = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName("java.util.regex", "Pattern") and
  call.getMethod().getName() = "matcher" and rule = "JDK_PATTERN_MATCHER_INPUT_ARG0" and
  mechanism = "JAVA_PATTERN_MATCHER" and index = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName("java.lang", "String") and
  call.getMethod().getName() = ["matches", "replaceAll", "replaceFirst", "split"] and
  rule = "JDK_STRING_REGEX_ARG0" and
  mechanism = "JAVA_STRING_" + call.getMethod().getName() and index = 0
}

predicate deserializationEffect(MethodCall call, string rule, string mechanism, int index) {
  call.getMethod().getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
  call.getMethod().getName() = ["readObject", "readUnshared"] and
  rule = "JDK_OBJECT_INPUT_STREAM_RECEIVER" and
  mechanism = "JAVA_OBJECT_INPUT_STREAM_" + call.getMethod().getName() and index = -1
  or
  call.getMethod().getDeclaringType().hasQualifiedName("java.beans", "XMLDecoder") and
  call.getMethod().getName() = "readObject" and rule = "JDK_XML_DECODER_RECEIVER" and
  mechanism = "JAVA_XML_DECODER_READ_OBJECT" and index = -1
}

predicate networkOutputEffect(MethodCall call, string rule, string mechanism, int index) {
  call.getMethod().getDeclaringType().hasQualifiedName("java.net", "URL") and
  call.getMethod().getName() = ["openConnection", "openStream"] and
  rule = "JDK_URL_REQUEST_RECEIVER" and
  mechanism = "JAVA_URL_" + call.getMethod().getName() and index = -1
  or
  call.getMethod().getDeclaringType().hasQualifiedName("java.net", "URLConnection") and
  call.getMethod().getName() = "connect" and rule = "JDK_URL_CONNECTION_RECEIVER" and
  mechanism = "JAVA_URL_CONNECTION_CONNECT" and index = -1
  or
  call.getMethod().getDeclaringType().hasQualifiedName("java.net.http", "HttpClient") and
  call.getMethod().getName() = ["send", "sendAsync"] and
  rule = "JDK_HTTP_CLIENT_REQUEST_ARG0" and
  mechanism = "JAVA_HTTP_CLIENT_" + call.getMethod().getName() and index = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName(
    "org.springframework.web.client", ["RestOperations", "RestTemplate"]
  ) and call.getMethod().getName() = [
    "getForObject", "getForEntity", "postForObject", "postForEntity", "put", "delete",
    "exchange", "headForHeaders", "optionsForAllow"
  ] and rule = "SPRING_REST_OPERATIONS_URL_ARG0" and
  mechanism = "SPRING_REST_" + call.getMethod().getName() and index = 0
}

predicate cryptographicConfigurationEffect(
  MethodCall call, string rule, string mechanism, int index
) {
  call.getMethod().getDeclaringType().hasQualifiedName("javax.crypto", ["Cipher", "KeyGenerator"]) and
  call.getMethod().getName() = "getInstance" and rule = "JCA_ALGORITHM_NAME_ARG0" and
  mechanism = "JCA_" + call.getMethod().getDeclaringType().getName() + "_GET_INSTANCE" and index = 0
  or
  call.getMethod().getDeclaringType().hasQualifiedName(
    "java.security",
    ["MessageDigest", "Signature", "KeyPairGenerator", "KeyFactory", "AlgorithmParameters"]
  ) and call.getMethod().getName() = "getInstance" and rule = "JCA_ALGORITHM_NAME_ARG0" and
  mechanism = "JCA_" + call.getMethod().getDeclaringType().getName() + "_GET_INSTANCE" and index = 0
}

predicate securityEffectCall(
  MethodCall call, string effectType, string rule, string mechanism, int index
) {
  filesystemEffect(call, rule, mechanism, index) and effectType = "FILESYSTEM_ACCESS"
  or processEffect(call, rule, mechanism, index) and effectType = "PROCESS_EXECUTION"
  or renderingEffect(call, rule, mechanism, index) and effectType = "RENDERING"
  or dynamicEvaluationEffect(call, rule, mechanism, index) and effectType = "DYNAMIC_EVALUATION"
  or regexEvaluationEffect(call, rule, mechanism, index) and effectType = "REGEX_EVALUATION"
  or deserializationEffect(call, rule, mechanism, index) and effectType = "DESERIALIZATION"
  or networkOutputEffect(call, rule, mechanism, index) and effectType = "NETWORK_OUTPUT"
  or cryptographicConfigurationEffect(call, rule, mechanism, index) and
    effectType = "CRYPTOGRAPHIC_CONFIGURATION"
}

predicate securityEffectType(string effectType) {
  effectType = [
    "FILESYSTEM_ACCESS", "PROCESS_EXECUTION", "RENDERING", "DYNAMIC_EVALUATION",
    "REGEX_EVALUATION", "DESERIALIZATION", "NETWORK_OUTPUT",
    "CRYPTOGRAPHIC_CONFIGURATION"
  ]
}

string seCallableIdentity(Callable callable) {
  result = callable.getDeclaringType().getQualifiedName() + "." + callable.getName() +
    "/" + callable.getNumberOfParameters().toString()
}

string seCalleeIdentity(MethodCall call) {
  result = call.getMethod().getQualifiedName() + "/" +
    call.getMethod().getNumberOfParameters().toString()
}

string seCallIdentity(MethodCall call) {
  result = seCalleeIdentity(call) + "@" +
    call.getLocation().getFile().getRelativePath() + ":" +
    call.getLocation().getStartLine().toString()
}

string seCallEntity(MethodCall call) {
  result = call.getEnclosingCallable().getDeclaringType().getQualifiedName() + "." +
    call.getEnclosingCallable().getName() + " -> " + call.getMethod().getQualifiedName()
}

predicate seCriticalRole(int index, string role) {
  index = -1 and role = "receiver"
  or index = 0 and role = "arg0"
  or index = 1 and role = "arg1"
}

predicate seAnchorKind(int index, string anchorKind) {
  index = -1 and anchorKind = "RECEIVER"
  or index = [0, 1] and anchorKind = "CALL_ARGUMENT"
}
