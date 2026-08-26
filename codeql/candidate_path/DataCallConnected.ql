/**
 * @name W1-E1 data/call candidate path
 * @description Emits only interprocedural CodeQL dataflow paths between frozen P0-A anchors.
 * @kind path-problem
 * @problem.severity recommendation
 * @id java/w1-e1-data-call-candidate-path
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import candidate_path.EndpointCandidates

module W1E1DataCallConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(string file, int line | externalInputNode(source, file, line))
  }

  predicate isSink(DataFlow::Node sink) {
    exists(string file, int line | securityEffectNode(sink, file, line))
  }
}

module W1E1DataCallFlow = TaintTracking::Global<W1E1DataCallConfig>;

from DataFlow::Node source, DataFlow::Node sink
where W1E1DataCallFlow::flow(source, sink)
select sink.asExpr(), source.asExpr(), sink.asExpr(),
  "W1-E1 data/call candidate path from $@ to $@.",
  source.asExpr(), "external input candidate",
  sink.asExpr(), "security effect candidate"
