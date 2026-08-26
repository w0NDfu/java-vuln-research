/**
 * @name W1-E1 data/call candidate path
 * @description Emits only interprocedural CodeQL dataflow paths between frozen P0-A anchors.
 * @kind table
 * @problem.severity recommendation
 * @id java/w1-e1-data-call-candidate-path
 */
import java
import semmle.code.java.dataflow.DataFlow
import candidate_path.EndpointCandidates

from DataFlow::Node source, DataFlow::Node sink,
  string sourceEntity, string sourceFile, int sourceLine,
  string sak, string svr, string smi, string sci, int sai, string saf, int sal, string smr,
  string effectEntity, string effectFile, int effectLine,
  string eak, string evr, string emi, string eci, int eai, string eaf, int eal, string emr
where
  externalInputAnalysisAnchor(source, sourceEntity, sourceFile, sourceLine,
    sak, svr, smi, sci, sai, saf, sal, smr) and
  securityEffectAnalysisAnchor(sink, effectEntity, effectFile, effectLine,
    eak, evr, emi, eci, eai, eaf, eal, emr) and
  W1E1ConnectedFlow::flow(source, sink)
select sourceEntity, sourceFile, sourceLine, effectEntity, effectFile, effectLine
