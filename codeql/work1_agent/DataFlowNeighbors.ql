/** Work1 V11 bounded-at-tool-boundary one-step base data-flow neighbors. */
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

from DataFlow::Node source, DataFlow::Node target, string file, int startLine, int endLine,
  string edgeKind
where
  DataFlow::localFlowStep(source, target) and
  (targetNode(source) and edgeKind = "FORWARD" or targetNode(target) and edgeKind = "BACKWARD") and
  nodeLocation(target, file, startLine, endLine)
select nodeId(source), nodeId(target), edgeKind, file, startLine, endLine, ""
