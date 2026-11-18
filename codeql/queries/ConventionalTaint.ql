/**
 * @name Conventional taint tracking from prompt slots to sinks
 * @description CodeQL's taint tracking as shipped, without any additional step and without a summary for the
 *              LLM calls: from the expressions on the lines where a placeholder is inserted into a prompt to
 *              the arguments that the sink on a sink line consumes. One row per file, slot line, and sink line.
 * @kind table
 * @id prism-rq2/conventional-taint
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import Facts

predicate isLlmCall(Call c) {
  exists(string f, int l | srcLine(f, l, _) and c.getLocation().getFile().getBaseName() = f and c.getLocation().getStartLine() = l)
}

predicate nested(Call c) {
  exists(Call o | o != c and o.getLocation().getFile() = c.getLocation().getFile() and
    o.getLocation().getStartLine() = c.getLocation().getStartLine() and c.getParentNode+() = o)
}

predicate callOn(Call c, string f, int l) {
  c.getLocation().getFile().getBaseName() = f and c.getLocation().getStartLine() = l
}

/** The arguments of the sink call that a sink of the given type acts on (as in LlmOutputToSink.ql). */
predicate sinkArg(DataFlow::Node n, Call c, string k) {
  k = "command-injection" and (n.asExpr() = c.getAnArg() or n.asExpr() = c.getAKeyword().getValue())
  or
  k = "ssrf" and (n.asExpr() = c.getArg(0) or exists(Keyword kw | kw = c.getAKeyword() and kw.getArg() = "url" and n.asExpr() = kw.getValue()))
  or
  k in ["sql-injection", "code-injection", "unsafe-deserialization"] and
  (n.asExpr() = c.getArg(0) or exists(Keyword kw | kw = c.getAKeyword() and
    kw.getArg() = ["sql", "query", "statement", "source", "code", "stream", "data"] and n.asExpr() = kw.getValue()))
}

predicate onSink(DataFlow::Node n, string f, int l) {
  exists(Call c, string k | sinkKind(f, l, k) and callOn(c, f, l) and not nested(c) and sinkArg(n, c, k))
}

/** The LLM call itself, or an expression that contains it. */
predicate llmSide(Expr e) { exists(Call c | isLlmCall(c) | e = c or c.getParentNode+() = e) }

predicate stored(Expr e) {
  e.(Name).getCtx() instanceof Store or e.(Attribute).getCtx() instanceof Store or e.(Subscript).getCtx() instanceof Store or
  e.(Tuple).getCtx() instanceof Store or e.(List).getCtx() instanceof Store or e.(Starred).getCtx() instanceof Store
}

/** An expression on a slot line or inside the arguments of a call that starts there; not the LLM call, not an assignment target. */
predicate slotSrc(DataFlow::Node n, string f, int l) {
  slotLine(f, l) and
  exists(Expr e | e = n.asExpr() and e.getLocation().getFile().getBaseName() = f |
    (
      e.getLocation().getStartLine() = l
      or
      exists(Call c, AstNode a | callOn(c, f, l) and a = c.getAChildNode() and a != c.getFunc() and e = a.getAChildNode*())
    ) and
    not llmSide(e) and not stored(e) and not e.(Name).getId() = ["self", "cls"]
  )
}

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { slotSrc(n, _, _) }

  predicate isSink(DataFlow::Node n) { onSink(n, _, _) }
}

module Flow = TaintTracking::Global<Cfg>;

from DataFlow::Node s, DataFlow::Node t, string f, int sl, int tl
where Flow::flow(s, t) and slotSrc(s, f, sl) and onSink(t, f, tl)
select f, sl, tl
