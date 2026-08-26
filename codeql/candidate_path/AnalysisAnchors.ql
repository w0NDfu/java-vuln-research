/** @name W1-E1 analysis-anchor mapping @kind table */
import java
import semmle.code.java.dataflow.DataFlow
import candidate_path.EndpointCandidates

from DataFlow::Node node, string side, string candidateEntity, string candidateFile,
  int candidateLine, string anchorKind, string valueRole, string methodIdentity,
  string mappedCallIdentity, int argumentIndex, string anchorFile, int anchorLine,
  string mappingReason
where
  externalInputAnalysisAnchor(node, candidateEntity, candidateFile, candidateLine,
    anchorKind, valueRole, methodIdentity, mappedCallIdentity, argumentIndex,
    anchorFile, anchorLine, mappingReason) and side = "INPUT"
  or
  securityEffectAnalysisAnchor(node, candidateEntity, candidateFile, candidateLine,
    anchorKind, valueRole, methodIdentity, mappedCallIdentity, argumentIndex,
    anchorFile, anchorLine, mappingReason) and side = "EFFECT"
select side, candidateEntity, candidateFile, candidateLine, anchorKind, valueRole,
  methodIdentity, mappedCallIdentity, argumentIndex, anchorFile, anchorLine,
  "MAPPED", mappingReason
