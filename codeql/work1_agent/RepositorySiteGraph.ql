/** Source-local navigation evidence. Edges do not establish path feasibility. */
import java
import semmle.code.java.dataflow.DataFlow

predicate endpoint(DataFlow::Node node, Element element) {
  element = node.asExpr() or element = node.asParameter()
}

predicate relation(Location source, Location target, string kind, string detail) {
  exists(Call call |
    source = call.getLocation() and target = call.getCallee().getLocation() and
    (
      (
        not call instanceof VirtualMethodCall or
        call.getCallee().(Method).isFinal() or call.getCallee().getDeclaringType().isFinal()
      ) and kind = "CODEQL_DIRECT_CALL"
      or
      call instanceof VirtualMethodCall and not call.getCallee().(Method).isFinal() and
      not call.getCallee().getDeclaringType().isFinal() and kind = "CODEQL_CALL"
    ) and detail = ""
  )
  or
  exists(VirtualMethodCall call, Method implementation |
    implementation.fromSource() and not implementation.isAbstract() and
    implementation.getAnOverride() = call.getMethod() and
    source = call.getLocation() and target = implementation.getLocation() and
    kind = "CODEQL_VIRTUAL_DISPATCH" and detail = ""
  )
  or
  exists(FieldWrite store, FieldRead load |
    store.getField() = load.getField() and store.getSite() != load.getSite() and
    source = store.getLocation() and target = load.getLocation() and kind = "CODEQL_FIELD_STATE" and
    detail = store.getField().getQualifiedName()
  )
  or
  exists(Call call, int index, Expr argument |
    argument = call.getArgument(index) and
    (argument.isCompileTimeConstant() or argument.(FieldAccess).getField() instanceof EnumConstant) and
    source = call.getLocation() and target = argument.getLocation() and
    kind = "CODEQL_CONSTANT_ARGUMENT" and detail = index.toString()
  )
  or
  exists(Call call |
    source = call.getLocation() and target = source and kind = "CODEQL_CALL_TARGET" and
    detail = call.getCallee().getDeclaringType().getQualifiedName()
  )
  or
  exists(ReturnStmt statement |
    source = statement.getEnclosingCallable().getLocation() and
    target = statement.getExpr().getLocation() and kind = "CODEQL_RETURN_SITE" and detail = ""
  )
  or
  exists(DataFlow::Node left, DataFlow::Node right, Element a, Element b |
    endpoint(left, a) and endpoint(right, b) and DataFlow::localFlowStep(left, right) and
    source = a.getLocation() and target = b.getLocation() and kind = "CODEQL_LOCAL_FLOW" and detail = ""
  )
  or
  exists(ControlFlowNode left, ControlFlowNode right |
    right = left.getASuccessor() and source = left.getLocation() and
    target = right.getLocation() and kind = "CODEQL_CFG" and detail = ""
  )
}

from Location source, Location target, string kind, string detail
where
  relation(source, target, kind, detail) and
  exists(Element a, Element b |
    a.fromSource() and b.fromSource() and source = a.getLocation() and target = b.getLocation()
  ) and source.getStartLine() > 0 and target.getStartLine() > 0
select kind, source.getFile().getRelativePath(), source.getStartLine(), source.getStartColumn(),
  target.getFile().getRelativePath(), target.getStartLine(), target.getStartColumn(), detail
