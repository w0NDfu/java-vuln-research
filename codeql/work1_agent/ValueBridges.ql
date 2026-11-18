/** Role-preserving potential taint transfers. Control feasibility and sanitizers are reviewed separately. */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

predicate constantArgument(Expr argument) {
  argument.isCompileTimeConstant() or argument.(FieldAccess).getField() instanceof EnumConstant
}

string locationKey(Location loc) {
  result = loc.getFile().getRelativePath() + ":" + loc.getStartLine().toString() + ":" +
    loc.getStartColumn().toString()
}

predicate inputPoint(DataFlow::Node node, Callable owner, Element site, string role, int index) {
  exists(Expr call |
    (call instanceof MethodCall or call instanceof ClassInstanceExpr) and
    owner = call.getEnclosingCallable() and owner.fromSource() and site = call and
    node.asExpr() = call and role = "CALL_RESULT" and index = -1
  )
  or
  exists(Parameter parameter |
    owner = parameter.getCallable() and owner.fromSource() and site = owner and
    node.asParameter() = parameter and role = "PARAMETER" and index = parameter.getPosition()
  )
}

predicate outputPoint(DataFlow::Node node, Callable owner, Element site, string role, int index) {
  exists(Call call |
    owner = call.getEnclosingCallable() and owner.fromSource() and site = call and
    node.asExpr() = call.getArgument(index) and not constantArgument(call.getArgument(index)) and role = "ARGUMENT"
  )
  or
  exists(MethodCall call |
    owner = call.getEnclosingCallable() and owner.fromSource() and site = call and
    node.asExpr() = call.getQualifier() and role = "CALL_RECEIVER" and index = -1
  )
  or
  exists(ReturnStmt statement |
    owner = statement.getEnclosingCallable() and owner.fromSource() and site = owner and
    node.asExpr() = statement.getExpr() and role = "RETURN" and index = -1
  )
}

predicate directTarget(Call call, Callable target) {
  call.getCallee() = target and target.fromSource() and
  (not call instanceof VirtualMethodCall or target.(Method).isFinal() or target.getDeclaringType().isFinal())
}

Parameter argumentParameter(Call call, Callable target, int index) {
  exists(call.getArgument(index)) and
  (
    result = target.getParameter(index)
    or
    target.isVarargs() and result = target.getParameter(target.getVaragsParameterIndex()) and
    index >= result.getPosition()
  )
}

predicate witnessedTransfer(
  Element source, string fromRole, int fromIndex, Element sink, string toRole, int toIndex,
  Location witness, Location end
) {
  exists(DataFlow::Node input, DataFlow::Node output, Callable owner |
    inputPoint(input, owner, source, fromRole, fromIndex) and
    outputPoint(output, owner, sink, toRole, toIndex) and
    TaintTracking::localTaint(input, output) and
    witness = input.getLocation() and end = output.getLocation()
  )
  or
  exists(MethodCall call, Method target, Parameter parameter, ReturnStmt statement |
    call.getEnclosingCallable().fromSource() and directTarget(call, target) and
    parameter = target.getParameter(fromIndex) and exists(call.getArgument(fromIndex)) and
    statement.getEnclosingCallable() = target and
    TaintTracking::localTaint(DataFlow::parameterNode(parameter), DataFlow::exprNode(statement.getExpr())) and
    source = call and sink = call and fromRole = "ARGUMENT" and toRole = "CALL_RESULT" and toIndex = -1 and
    witness = parameter.getLocation() and end = statement.getLocation()
  )
  or
  exists(Call call, Callable target, Parameter parameter |
    call.getEnclosingCallable().fromSource() and directTarget(call, target) and
    parameter = target.getParameter(fromIndex) and exists(call.getArgument(fromIndex)) and
    not (target.isVarargs() and parameter.getPosition() = target.getVaragsParameterIndex()) and
    source = call and sink = target and fromRole = "ARGUMENT" and toRole = "PARAMETER" and
    toIndex = parameter.getPosition() and witness = call.getLocation() and end = call.getLocation()
  )
  or
  exists(MethodCall call, Method target, ReturnStmt statement |
    call.getEnclosingCallable().fromSource() and directTarget(call, target) and
    statement.getEnclosingCallable() = target and exists(statement.getExpr()) and
    source = target and sink = call and fromRole = "RETURN" and toRole = "CALL_RESULT" and
    fromIndex = -1 and toIndex = -1 and witness = statement.getLocation() and end = witness
  )
}

predicate virtualTarget(VirtualMethodCall call, Method target) {
  call.getEnclosingCallable().fromSource() and target.fromSource() and not target.isAbstract() and
  (target = call.getMethod() or target.getAnOverride() = call.getMethod()) and
  not (target = call.getMethod() and
    (target.isFinal() or target.getDeclaringType().isFinal()))
}

predicate collectionTransfer(MethodCall store, int valueIndex, MethodCall load) {
  store.getQualifier().getUnderlyingExpr().(VarAccess).getVariable() =
    load.getQualifier().getUnderlyingExpr().(VarAccess).getVariable() and
  exists(RefType container |
    container = store.getQualifier().getType().(RefType).getASupertype*().getSourceDeclaration() and
    (
      container.hasQualifiedName("java.util", "Map") and store.getMethod().hasName("put") and
      load.getMethod().hasName("get") and valueIndex = 1
      or
      container.hasQualifiedName("java.util", "List") and load.getMethod().hasName("get") and
      (
        store.getMethod().hasName("add") and valueIndex = store.getNumArgument() - 1
        or
        store.getMethod().hasName("set") and valueIndex = 1
      )
    )
  )
}

predicate callbackTarget(ClassInstanceExpr allocation, Method target) {
  target.fromSource() and not target.isStatic() and not target.isAbstract() and
  target.getDeclaringType() = allocation.getConstructedType().getASupertype*() and
  not target.getName() = ["toString", "hashCode", "equals", "getClass"] and
  not (target.getNumberOfParameters() = 0 and target.getName().regexpMatch("(get|is|has)[A-Z].*"))
}

predicate captures(Parameter parameter, FieldWrite store) {
  exists(Constructor constructor |
    constructor = parameter.getCallable() and store.getSite() = constructor and
    not store.getField().isStatic() and
    TaintTracking::localTaint(DataFlow::parameterNode(parameter), DataFlow::exprNode(store.getASource()))
  )
  or
  exists(Call delegation, int index, Constructor parent |
    (delegation instanceof ThisConstructorInvocationStmt or delegation instanceof SuperConstructorInvocationStmt) and
    delegation.getEnclosingCallable() = parameter.getCallable() and parent = delegation.getCallee() and
    TaintTracking::localTaint(DataFlow::parameterNode(parameter),
      DataFlow::exprNode(delegation.getArgument(index))) and
    captures(argumentParameter(delegation, parent, index), store)
  )
}

predicate fluentUpdate(MethodCall update) {
  exists(Method target, ReturnStmt stmt |
    target = update.getMethod().getSourceDeclaration() and target.fromSource() and not target.isStatic() and
    stmt.getEnclosingCallable() = target and
    (
      stmt.getExpr().getUnderlyingExpr() instanceof ThisAccess
      or
      stmt.getExpr().(ClassInstanceExpr).getConstructedType() = target.getDeclaringType()
    )
  )
}

predicate laterReceiver(MethodCall update, MethodCall use) {
  update != use and update.getEnclosingCallable() = use.getEnclosingCallable() and
  (
    DataFlow::localFlow(DataFlow::exprNode(update), DataFlow::exprNode(use.getQualifier()))
    or
    update.getQualifier().getUnderlyingExpr().(VarAccess).getVariable() =
      use.getQualifier().getUnderlyingExpr().(VarAccess).getVariable() and
    (
      update.getLocation().getStartLine() < use.getLocation().getStartLine()
      or
      update.getLocation().getStartLine() = use.getLocation().getStartLine() and
      update.getLocation().getStartColumn() < use.getLocation().getStartColumn()
    )
  )
}

predicate arrayTransfer(DataFlow::Node input, DataFlow::Node output, Location site) {
  exists(ArrayCreationExpr array |
    TaintTracking::localTaint(input, DataFlow::exprNode(array.getInit().getAnInit())) and
    TaintTracking::localTaint(DataFlow::exprNode(array), output) and site = array.getLocation()
  )
  or
  exists(ArrayAccess access |
    TaintTracking::localTaint(input, DataFlow::exprNode(access.getArray())) and
    TaintTracking::localTaint(DataFlow::exprNode(access), output) and site = access.getLocation()
  )
}

predicate relaxedTransfer(
  Element source, string fromRole, int fromIndex, Element sink, string toRole, int toIndex,
  Location first, Location last, string kind, string group
) {
  exists(VirtualMethodCall call, Method target |
    virtualTarget(call, target) and kind = "cha_poly_bridge" and group = locationKey(call.getLocation()) and
    (
      source = call and sink = target and fromRole = "ARGUMENT" and toRole = "PARAMETER" and
      toIndex = argumentParameter(call, target, fromIndex).getPosition() and
      first = call.getLocation() and last = first
      or
      source = target and sink = call and fromRole = "RETURN" and toRole = "CALL_RESULT" and
      fromIndex = -1 and toIndex = -1 and
      exists(ReturnStmt stmt | stmt.getEnclosingCallable() = target and first = stmt.getLocation()) and last = first
    )
  )
  or
  exists(FieldWrite store, FieldRead load, DataFlow::Node input, DataFlow::Node output |
    store.getField() = load.getField() and store.getSite() != load.getSite() and
    inputPoint(input, store.getSite(), source, fromRole, fromIndex) and
    outputPoint(output, load.getSite(), sink, toRole, toIndex) and
    TaintTracking::localTaint(input, DataFlow::exprNode(store.getASource())) and
    TaintTracking::localTaint(DataFlow::exprNode(load), output) and
    first = store.getLocation() and last = load.getLocation() and kind = "field_state_bridge" and
    group = store.getField().getQualifiedName()
  )
  or
  exists(MethodCall store, MethodCall load |
    collectionTransfer(store, fromIndex, load) and store != load and
    store.getEnclosingCallable().fromSource() and load.getEnclosingCallable().fromSource() and
    source = store and sink = load and fromRole = "ARGUMENT" and toRole = "CALL_RESULT" and toIndex = -1 and
    first = store.getLocation() and last = load.getLocation() and kind = "container_state_bridge" and
    group = locationKey(store.getQualifier().getUnderlyingExpr().(VarAccess).getVariable().getLocation())
  )
  or
  exists(ClassInstanceExpr allocation, Constructor constructor, Method target |
    constructor = allocation.getCallee() and constructor.fromSource() and
    allocation.getEnclosingCallable().fromSource() and callbackTarget(allocation, target) and
    exists(argumentParameter(allocation, constructor, fromIndex)) and
    source = allocation and fromRole = "ARGUMENT" and kind = "closure_object_bridge" and
    group = locationKey(allocation.getLocation()) and
    (
      sink = target and toRole = "RECEIVER" and toIndex = -1 and
      first = allocation.getLocation() and last = target.getLocation()
      or
      exists(FieldWrite store, FieldRead load, DataFlow::Node output |
        captures(argumentParameter(allocation, constructor, fromIndex), store) and
        load.getField() = store.getField() and load.getSite() = target and
        outputPoint(output, target, sink, toRole, toIndex) and
        TaintTracking::localTaint(DataFlow::exprNode(load), output) and
        first = store.getLocation() and last = load.getLocation()
      )
    )
  )
  or
  exists(MethodCall update |
    update.getEnclosingCallable().fromSource() and fluentUpdate(update) and exists(update.getArgument(fromIndex)) and
    source = update and fromRole = "ARGUMENT" and toIndex = -1 and
    kind = "builder_receiver_bridge" and group = locationKey(update.getLocation()) and first = update.getLocation() and
    (
      sink = update and toRole = "CALL_RESULT" and last = first
      or
      sink = update and toRole = "CALL_RECEIVER" and exists(update.getQualifier()) and last = first
      or
      exists(MethodCall use |
        laterReceiver(update, use) and sink = use and toRole = "CALL_RECEIVER" and last = use.getLocation()
      )
    )
  )
  or
  exists(Call call, Callable target |
    call.getEnclosingCallable().fromSource() and directTarget(call, target) and target.isVarargs() and
    toIndex = argumentParameter(call, target, fromIndex).getPosition() and
    toIndex = target.getVaragsParameterIndex() and
    source = call and sink = target and fromRole = "ARGUMENT" and toRole = "PARAMETER" and
    first = call.getLocation() and last = target.getParameter(toIndex).getLocation() and
    kind = "array_varargs_bridge" and group = locationKey(call.getLocation())
  )
  or
  exists(DataFlow::Node input, DataFlow::Node output, Callable owner |
    inputPoint(input, owner, source, fromRole, fromIndex) and
    outputPoint(output, owner, sink, toRole, toIndex) and arrayTransfer(input, output, first) and
    last = first and kind = "array_varargs_bridge" and group = locationKey(first)
  )
}

from Element source, string fromRole, int fromIndex, Element sink, string toRole, int toIndex,
  Location witness, Location end, string kind, string group
where
  (fromRole != "ARGUMENT" or not constantArgument(source.(Call).getArgument(fromIndex))) and
  (
    witnessedTransfer(source, fromRole, fromIndex, sink, toRole, toIndex, witness, end) and kind = "static" and group = ""
    or
    relaxedTransfer(source, fromRole, fromIndex, sink, toRole, toIndex, witness, end, kind, group)
  )
select source.getFile().getRelativePath(), source.getLocation().getStartLine(), source.getLocation().getStartColumn(),
  source.getLocation().getEndLine(), source.getLocation().getEndColumn(), fromRole, fromIndex,
  sink.getFile().getRelativePath(), sink.getLocation().getStartLine(), sink.getLocation().getStartColumn(),
  sink.getLocation().getEndLine(), sink.getLocation().getEndColumn(), toRole, toIndex,
  witness.getFile().getRelativePath(), witness.getStartLine(), end.getStartLine(),
  kind, end.getFile().getRelativePath(), group
