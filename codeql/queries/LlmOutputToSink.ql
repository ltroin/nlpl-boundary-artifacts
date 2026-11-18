/**
 * @name Flows from LLM outputs to sink arguments and prompt slots
 * @description Taint tracking from the value of every located LLM API call to (a) the arguments that the
 *              sink on a sink line consumes and (b) the lines on which a placeholder is inserted into a
 *              prompt. One row per file, line of the LLM call, and line of the target.
 * @kind table
 * @id prism-rq2/llm-output-to-sink
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import Facts

predicate isLlmCall(Call c) {
  exists(string f, int l | srcLine(f, l, _) and c.getLocation().getFile().getBaseName() = f and c.getLocation().getStartLine() = l)
}

/** The outermost call that starts on line l of file f. */
predicate outerCall(Call c, string f, int l) {
  c.getLocation().getFile().getBaseName() = f and c.getLocation().getStartLine() = l and
  not exists(Call o | o != c and o.getLocation().getFile() = c.getLocation().getFile() and
    o.getLocation().getStartLine() = l and c.getParentNode+() = o)
}

/** The arguments of the sink call that a sink of the given type acts on. */
predicate onSink(DataFlow::Node n, string f, int l) {
  exists(Call c, string k | sinkKind(f, l, k) and outerCall(c, f, l) |
    k = "command-injection" and (n.asExpr() = c.getAnArg() or n.asExpr() = c.getAKeyword().getValue())
    or
    k = "ssrf" and (n.asExpr() = c.getArg(0) or exists(Keyword kw | kw = c.getAKeyword() and kw.getArg() = "url" and n.asExpr() = kw.getValue()))
    or
    k in ["sql-injection", "code-injection", "unsafe-deserialization"] and
    (n.asExpr() = c.getArg(0) or exists(Keyword kw | kw = c.getAKeyword() and
      kw.getArg() = ["sql", "query", "statement", "source", "code", "stream", "data"] and n.asExpr() = kw.getValue()))
  )
}

/** An expression on a slot line, or an argument of a call that starts there. */
predicate onSlot(DataFlow::Node n, string f, int l) {
  slotLine(f, l) and
  (
    n.getLocation().getFile().getBaseName() = f and n.getLocation().getStartLine() = l
    or
    exists(Call c | c.getLocation().getFile().getBaseName() = f and c.getLocation().getStartLine() = l and
      (n.asExpr() = c.getAnArg() or n.asExpr() = c.getAKeyword().getValue()))
  )
}

predicate target(DataFlow::Node n, string f, int l) { onSink(n, f, l) or onSlot(n, f, l) }

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { exists(Call c | n.asExpr() = c and isLlmCall(c)) }

  predicate isSink(DataFlow::Node n) { target(n, _, _) }

  /**
   * Library calls without a model keep taint: the result of a call other than a located LLM call is tainted
   * when an argument or the receiver is tainted, and attribute and subscript reads keep the taint of the object.
   * The located LLM calls are not passed. Whether a placeholder passes an LLM call is decided outside the
   * query (scripts/rq2_codeql_rows.py).
   */
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
