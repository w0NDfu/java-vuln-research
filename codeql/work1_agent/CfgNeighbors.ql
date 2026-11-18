/** Work1 V11 immediate control-flow predecessors and successors. */
import java

predicate targetNode(ControlFlowNode n) {
  n.getLocation().getFile().getRelativePath() = {{PATH}} and
  n.getLocation().getStartLine() <= {{END_LINE}} and
  n.getLocation().getEndLine() >= {{START_LINE}}
}

string nodeId(ControlFlowNode n) {
  result = n.getLocation().getFile().getRelativePath() + ":" +
    n.getLocation().getStartLine().toString() + ":" + n.toString()
}

string callableId(ControlFlowNode n) {
  result = n.getEnclosingCallable().getDeclaringType().getQualifiedName() + "." +
    n.getEnclosingCallable().getName() + "/" +
    n.getEnclosingCallable().getNumberOfParameters().toString()
}

from ControlFlowNode source, ControlFlowNode target, string edgeKind
where
  (targetNode(source) and target = source.getASuccessor() and edgeKind = "SUCCESSOR")
  or
  (targetNode(target) and source = target.getAPredecessor() and edgeKind = "PREDECESSOR")
select nodeId(source), nodeId(target), edgeKind,
  target.getLocation().getFile().getRelativePath(),
  target.getLocation().getStartLine(), target.getLocation().getEndLine(), callableId(target)
