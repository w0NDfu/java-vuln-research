/** Seed-independent structural candidates for Work1 P0-B.
 *
 * This module deliberately does not import the frozen Route-A endpoint models.
 * It adds no propagation semantics; all connections use the CodeQL base graph.
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

string callableIdentity(Callable callable) {
  result = callable.getDeclaringType().getQualifiedName() + "." + callable.getName() +
    "/" + callable.getNumberOfParameters().toString()
}

string parameterEntity(Parameter p) {
  result = callableIdentity(p.getCallable()) + " parameter " + p.getName()
}

string callIdentity(MethodCall call) {
  result = call.getMethod().getQualifiedName() + "/" +
    call.getMethod().getNumberOfParameters().toString() + "@" +
    call.getLocation().getFile().getRelativePath() + ":" +
    call.getLocation().getStartLine().toString()
}

string callEntity(MethodCall call) {
  result = callableIdentity(call.getEnclosingCallable()) + " -> " +
    call.getMethod().getQualifiedName()
}

predicate annotatedBoundary(Method method, string reason, string evidenceKind, string confidence) {
  exists(Annotation a |
    a = method.getAnAnnotation() and
    (
      a.getType().hasQualifiedName("org.springframework.web.bind.annotation",
        ["RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping"])
      or a.getType().hasQualifiedName(["javax.ws.rs", "jakarta.ws.rs"],
        ["Path", "GET", "POST", "PUT", "DELETE", "PATCH"])
    ) and
    reason = "ANNOTATED_BOUNDARY" and evidenceKind = "FRAMEWORK_HANDLER_ANNOTATION" and
    confidence = "STRUCTURE_HIGH"
  )
  or
  exists(Annotation a |
    a = method.getAnAnnotation() and
    a.getType().hasQualifiedName(
      ["org.springframework.context.event", "org.springframework.kafka.annotation",
       "org.springframework.amqp.rabbit.annotation", "org.springframework.jms.annotation",
       "org.springframework.messaging.handler.annotation", "javax.websocket", "jakarta.websocket"],
      ["EventListener", "KafkaListener", "RabbitListener", "JmsListener", "MessageMapping", "OnMessage"]
    ) and reason = "MESSAGE_EVENT_BOUNDARY" and
    evidenceKind = "MESSAGE_OR_EVENT_HANDLER_ANNOTATION" and confidence = "STRUCTURE_HIGH"
  )
}

predicate requestLikeType(Parameter p) {
  p.getType().getName().matches("%Request")
  or p.getType().getName().matches("%Context")
  or p.getType().getName().matches("%Event")
  or p.getType().getName().matches("%Message")
  or p.getType().getName().matches("%Payload")
  or exists(RefType type |
    type = p.getType() and
    type.hasQualifiedName(
      ["javax.servlet", "jakarta.servlet", "javax.servlet.http", "jakarta.servlet.http"],
      ["ServletRequest", "HttpServletRequest"]
    )
  )
}

predicate callbackOrOverride(Parameter p, string reason, string evidenceKind, string confidence) {
  exists(Method method, Method base |
    p.getCallable() = method and method.overrides(base) and requestLikeType(p) and
    reason = "OVERRIDE_PARAMETER" and evidenceKind = "OVERRIDDEN_REQUEST_LIKE_PARAMETER" and
    confidence = "STRUCTURE_HIGH"
  )
  or
  exists(Method method |
    p.getCallable() = method and requestLikeType(p) and
    method.getName() = ["onMessage", "onEvent", "handle", "handleRequest", "accept", "apply", "invoke"] and
    not exists(Method base | method.overrides(base)) and
    reason = "CALLBACK_PARAMETER" and evidenceKind = "CALLBACK_REQUEST_LIKE_PARAMETER" and
    confidence = "STRUCTURE_MEDIUM"
  )
}

predicate routeBInputCandidate(
  DataFlow::Node node, Parameter p, string reason, string evidenceKind, string confidence
) {
  node.asParameter() = p and p.fromSource() and
  (
    exists(Method method | p.getCallable() = method and annotatedBoundary(method, reason, evidenceKind, confidence))
    or callbackOrOverride(p, reason, evidenceKind, confidence)
    or requestLikeType(p) and
      not exists(Method method, string r, string e, string c |
        p.getCallable() = method and annotatedBoundary(method, r, e, c)) and
      not exists(string r, string e, string c | callbackOrOverride(p, r, e, c)) and
      reason = "REQUEST_CONTEXT_TYPE" and evidenceKind = "REQUEST_LIKE_PARAMETER_TYPE" and
      confidence = "OPEN_CANDIDATE"
  )
}

predicate sensitiveAbstraction(Method method, string reason, string effectCategory, string evidenceKind, string confidence) {
  (
    method.getDeclaringType().getName().matches("%Repository")
    or method.getDeclaringType().getName().matches("%Store")
    or method.getDeclaringType().getName().matches("%Storage")
    or method.getDeclaringType().getName().matches("%FileSystem")
  ) and method.getName() = ["save", "store", "write", "put", "delete", "remove", "load", "read"] and
  reason = "STORAGE_ABSTRACTION" and effectCategory = "STORAGE" and
  evidenceKind = "SENSITIVE_RECEIVER_AND_METHOD" and confidence = "STRUCTURE_HIGH"
  or
  (
    method.getDeclaringType().getName().matches("%CommandExecutor")
    or method.getDeclaringType().getName().matches("%ProcessExecutor")
    or method.getDeclaringType().getName().matches("%Shell")
  ) and method.getName() = ["execute", "exec", "run", "start"] and
  reason = "PROCESS_ABSTRACTION" and effectCategory = "PROCESS_EXECUTION" and
  evidenceKind = "PROCESS_RECEIVER_AND_METHOD" and confidence = "STRUCTURE_HIGH"
  or
  (
    method.getDeclaringType().getName().matches("%Template")
    or method.getDeclaringType().getName().matches("%Renderer")
    or method.getDeclaringType().getName().matches("%ResponseWriter")
  ) and method.getName() = ["render", "process", "evaluate", "write", "print", "send"] and
  reason = "FRAMEWORK_OUTPUT" and effectCategory = "OUTPUT" and
  evidenceKind = "OUTPUT_RECEIVER_AND_METHOD" and confidence = "STRUCTURE_MEDIUM"
  or
  (
    method.getDeclaringType().getName().matches("%Client")
    or method.getDeclaringType().getName().matches("%Gateway")
    or method.getDeclaringType().getName().matches("%Publisher")
  ) and method.getName() = ["send", "publish", "post", "put", "exchange", "execute"] and
  reason = "THIRD_PARTY_EFFECT" and effectCategory = "NETWORK_OR_MESSAGE_OUTPUT" and
  evidenceKind = "CLIENT_RECEIVER_AND_METHOD" and confidence = "STRUCTURE_MEDIUM"
  or
  method.getDeclaringType().getName().matches("%Deserializer") and
  method.getName() = ["deserialize", "read", "parse"] and
  reason = "DYNAMIC_OPERATION" and effectCategory = "DESERIALIZATION" and
  evidenceKind = "DESERIALIZER_RECEIVER_AND_METHOD" and confidence = "STRUCTURE_HIGH"
}

predicate routeBEffectCandidate(
  DataFlow::Node node, MethodCall call, string reason, string effectCategory,
  string evidenceKind, string confidence, string valueRole, int argumentIndex
) {
  call.fromSource() and
  sensitiveAbstraction(call.getMethod(), reason, effectCategory, evidenceKind, confidence) and
  (
    exists(Expr arg |
      arg = call.getArgument(0) and node.asExpr() = arg and
      valueRole = "CALL_ARGUMENT" and argumentIndex = 0
    )
    or
    not exists(Expr arg | arg = call.getArgument(0)) and
    node.asExpr() = call.getQualifier() and valueRole = "RECEIVER" and argumentIndex = -1
  )
}

predicate nodeCallable(DataFlow::Node node, Callable callable) {
  exists(Parameter p | node.asParameter() = p and callable = p.getCallable())
  or exists(Expr expr | node.asExpr() = expr and callable = expr.getEnclosingCallable())
}

predicate directlyCalls(Callable caller, Callable callee) {
  exists(MethodCall call | call.getEnclosingCallable() = caller and call.getMethod() = callee)
}

predicate routeBPairGate(DataFlow::Node input, DataFlow::Node effect, int distance, string reason) {
  exists(Callable inputCallable, Callable effectCallable |
    nodeCallable(input, inputCallable) and nodeCallable(effect, effectCallable) and
    (
      inputCallable = effectCallable and distance = 0 and reason = "SAME_METHOD"
      or inputCallable != effectCallable and directlyCalls(inputCallable, effectCallable) and
        distance = 1 and reason = "INPUT_CALLS_EFFECT_REGION"
      or inputCallable != effectCallable and directlyCalls(effectCallable, inputCallable) and
        distance = 1 and reason = "EFFECT_CALLS_INPUT_REGION"
      or exists(Callable middle |
        directlyCalls(inputCallable, middle) and directlyCalls(middle, effectCallable) and
        distance = 2 and reason = "TWO_HOP_CALL_REGION")
      or inputCallable.getDeclaringType().getPackage().getName() =
        effectCallable.getDeclaringType().getPackage().getName() and
        distance = 3 and reason = "SAME_PACKAGE"
    )
  )
}

module RouteBFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Parameter p, string reason, string evidenceKind, string confidence |
      routeBInputCandidate(source, p, reason, evidenceKind, confidence))
  }

  predicate isSink(DataFlow::Node sink) {
    exists(MethodCall call, string reason, string effectCategory, string evidenceKind,
      string confidence, string valueRole, int argumentIndex |
      routeBEffectCandidate(sink, call, reason, effectCategory, evidenceKind, confidence,
        valueRole, argumentIndex))
  }
}

module RouteBFlow = TaintTracking::Global<RouteBFlowConfig>;
