/** Work1 V11 one-step neutral local data-flow facts. */
import java
import semmle.code.java.dataflow.DataFlow

predicate nodeLocation(DataFlow::Node n, string file, int startLine, int endLine) {
  exists(Expr e |
    n.asExpr() = e and file = e.getLocation().getFile().getRelativePath() and
    startLine = e.getLocation().getStartLine() and endLine = e.getLocation().getEndLine())
  or
  exists(Parameter p |
    n.asParameter() = p and file = p.getLocation().getFile().getRelativePath() and
    startLine = p.getLocation().getStartLine() and endLine = p.getLocation().getEndLine())
}

string nodeId(DataFlow::Node n) {
  exists(string file, int startLine, int endLine |
    nodeLocation(n, file, startLine, endLine) and
    result = file + ":" + startLine.toString() + ":" + n.toString())
}

predicate targetNode(DataFlow::Node n) {
  exists(string file, int startLine, int endLine |
    nodeLocation(n, file, startLine, endLine) and file = {{PATH}} and
    startLine <= {{END_LINE}} and endLine >= {{START_LINE}})
}

predicate nodeCallable(DataFlow::Node n, Callable c) {
  exists(Expr e | n.asExpr() = e and c = e.getEnclosingCallable())
  or exists(Parameter p | n.asParameter() = p and c = p.getCallable())
}

string callableId(DataFlow::Node n) {
  exists(Callable c |
    nodeCallable(n, c) and
    result = c.getDeclaringType().getQualifiedName() + "." + c.getName() + "/" +
      c.getNumberOfParameters().toString())
}

from DataFlow::Node source, DataFlow::Node target, string file, int startLine, int endLine
where
  targetNode(source) and DataFlow::localFlowStep(source, target) and
  nodeLocation(target, file, startLine, endLine)
select nodeId(source), nodeId(target), "DATAFLOW", file, startLine, endLine, callableId(target)
