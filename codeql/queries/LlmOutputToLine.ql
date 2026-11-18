/**
 * @name Flows from LLM outputs to sink lines and prompt slots (whole lines)
 * @description The same sources and steps as LlmOutputToSink.ql. A target is any expression on a sink or slot
 *              line, or any argument of a call that starts there. It is used to decide whether CodeQL connects
 *              some LLM output of the file to a sink at all. One row per file, line of the LLM call, and line
 *              of the target.
 * @kind table
 * @id prism-rq2/llm-output-to-line
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import Facts

predicate isLlmCall(Call c) {
  exists(string f, int l | srcLine(f, l, _) and c.getLocation().getFile().getBaseName() = f and c.getLocation().getStartLine() = l)
}

predicate target(DataFlow::Node n, string f, int l) {
  tgtLine(f, l, _) and
  (
    n.getLocation().getFile().getBaseName() = f and n.getLocation().getStartLine() = l
    or
    exists(Call c | c.getLocation().getFile().getBaseName() = f and c.getLocation().getStartLine() = l and
      (n.asExpr() = c.getAnArg() or n.asExpr() = c.getAKeyword().getValue()))
  )
}

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { exists(Call c | n.asExpr() = c and isLlmCall(c)) }

  predicate isSink(DataFlow::Node n) { target(n, _, _) }

  /** The same additional steps as in LlmOutputToSink.ql. */
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {
    exists(Call c | b.asExpr() = c and not isLlmCall(c) and
      (a.asExpr() = c.getAnArg() or a.asExpr() = c.getAKeyword().getValue() or a.asExpr() = c.getFunc().(Attribute).getObject()))
    or
    exists(Attribute at | b.asExpr() = at and a.asExpr() = at.getObject())
    or
    exists(Subscript sub | b.asExpr() = sub and a.asExpr() = sub.getObject())
  }
}

module Flow = TaintTracking::Global<Cfg>;

from DataFlow::Node s, DataFlow::Node t, string f, int sl, int tl
where Flow::flow(s, t) and
  s.getLocation().getFile().getBaseName() = f and sl = s.getLocation().getStartLine() and
  target(t, f, tl)
select f, sl, tl
