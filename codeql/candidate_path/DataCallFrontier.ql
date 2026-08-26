/**
 * @name W1-E1 structural frontier diagnostic
 * @description Emits structurally adjacent one-sided frontiers without adding a propagation edge.
 * @kind table
 * @id java/w1-e1-structural-frontier-diagnostic
 */
import java
import semmle.code.java.dataflow.DataFlow
import candidate_path.EndpointCandidates

from DataFlow::Node input, DataFlow::Node fw, DataFlow::Node bw, DataFlow::Node effect,
  string inputEntity, string inputFile, int inputLine,
  string iak, string ivr, string imi, string ici, int iai, string iaf, int ial, string imr,
  string effectEntity, string effectFile, int effectLine,
  string eak, string evr, string emi, string eci, int eai, string eaf, int eal, string emr,
  string fwKind, string fwEntity, string fwFile, int fwLine, string fwMethod,
  string bwKind, string bwEntity, string bwFile, int bwLine, string bwMethod,
  int distance, string reason
where
  externalInputAnalysisAnchor(input, inputEntity, inputFile, inputLine,
    iak, ivr, imi, ici, iai, iaf, ial, imr) and
  securityEffectAnalysisAnchor(effect, effectEntity, effectFile, effectLine,
    eak, evr, emi, eci, eai, eaf, eal, emr) and
  analysisNodeInfo(fw, fwKind, fwEntity, fwFile, fwLine, fwMethod) and
  analysisNodeInfo(bw, bwKind, bwEntity, bwFile, bwLine, bwMethod) and
  input != fw and bw != effect and fw != bw and
  W1E1ForwardFlow::flow(input, fw) and W1E1BackwardFlow::flow(bw, effect) and
  structuralRelation(fw, bw, distance, reason) and
  not W1E1ConnectedFlow::flow(input, effect)
select inputEntity, inputFile, inputLine, effectEntity, effectFile, effectLine,
  fwKind, fwEntity, fwFile, fwLine, fwMethod,
  bwKind, bwEntity, bwFile, bwLine, bwMethod, distance, reason
