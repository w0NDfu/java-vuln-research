/** @name W1-E1 one-sided input forward funnel @kind table */
import java
import semmle.code.java.dataflow.DataFlow
import candidate_path.EndpointCandidates

from DataFlow::Node source, DataFlow::Node reachable,
  string candidateEntity, string candidateFile, int candidateLine,
  string ak, string vr, string mi, string ci, int ai, string af, int al, string mr,
  string nodeKind, string nodeEntity, string nodeFile, int nodeLine, string nodeMethod
where
  externalInputAnalysisAnchor(source, candidateEntity, candidateFile, candidateLine,
    ak, vr, mi, ci, ai, af, al, mr) and
  analysisNodeInfo(reachable, nodeKind, nodeEntity, nodeFile, nodeLine, nodeMethod) and
  source != reachable and W1E1ForwardFlow::flow(source, reachable)
select candidateEntity, candidateFile, candidateLine, nodeKind, nodeEntity,
  nodeFile, nodeLine, nodeMethod
