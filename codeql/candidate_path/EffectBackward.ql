/** @name W1-E1 one-sided effect backward funnel @kind table */
import java
import semmle.code.java.dataflow.DataFlow
import candidate_path.EndpointCandidates

from DataFlow::Node reachable, DataFlow::Node sink,
  string candidateEntity, string candidateFile, int candidateLine,
  string ak, string vr, string mi, string ci, int ai, string af, int al, string mr,
  string nodeKind, string nodeEntity, string nodeFile, int nodeLine, string nodeMethod
where
  securityEffectAnalysisAnchor(sink, candidateEntity, candidateFile, candidateLine,
    ak, vr, mi, ci, ai, af, al, mr) and
  analysisNodeInfo(reachable, nodeKind, nodeEntity, nodeFile, nodeLine, nodeMethod) and
  reachable != sink and W1E1BackwardFlow::flow(reachable, sink)
select candidateEntity, candidateFile, candidateLine, nodeKind, nodeEntity,
  nodeFile, nodeLine, nodeMethod
