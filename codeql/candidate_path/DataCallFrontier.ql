/**
 * @name W1-E1 data/call frontier candidate
 * @description Emits direct caller-to-callee endpoint pairs without a solved dataflow path.
 * @kind table
 */
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import candidate_path.EndpointCandidates

module W1E1FrontierConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(string file, int line | externalInputNode(source, file, line))
  }

  predicate isSink(DataFlow::Node sink) {
    exists(string file, int line | securityEffectNode(sink, file, line))
  }
}

module W1E1FrontierFlow = TaintTracking::Global<W1E1FrontierConfig>;

from DataFlow::Node source, DataFlow::Node sink,
  Callable caller, Callable callee, MethodCall call,
  string sourceFile, int sourceLine, string effectFile, int effectLine
where
  externalInputNode(source, sourceFile, sourceLine) and
  securityEffectNode(sink, effectFile, effectLine) and
  inputCallable(source, caller) and
  effectCallable(sink, callee) and
  call.getEnclosingCallable() = caller and
  call.getMethod() = callee and
  not W1E1FrontierFlow::flow(source, sink)
select sourceFile, sourceLine, effectFile, effectLine,
  call.getLocation().getFile().getRelativePath(), call.getLocation().getStartLine(), "OTHER"
