/**
 * @name Full backward slice (data + control) from LLM call arguments
 * @description Computes a backward slice including both data dependencies
 *              (via taint tracking) and control dependencies (enclosing
 *              if/for/while/with/try conditions) from LLM API call arguments.
 *              No barriers applied.
 * @kind problem
 * @problem.severity recommendation
 * @id llm-boundary/full-slice-from-llm-input
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * Exclusion list: objects whose method calls are clearly NOT LLM calls.
 */
private predicate isExcludedObject(string name) {
  name = ["os", "subprocess", "re", "json", "requests", "urllib",
          "db", "cursor", "session", "engine", "conn", "pwd_file",
          "sys", "math", "random", "logging", "logger", "log",
          "Path", "pathlib", "shutil", "glob", "csv", "yaml",
          "pickle", "struct", "io", "socket", "http", "threading",
          "time", "datetime", "collections", "itertools", "functools",
          "hashlib", "hmac", "base64", "codecs", "copy", "pprint",
          "unittest", "pytest", "mock", "torch", "np", "numpy",
          "pd", "pandas", "tf", "tensorflow", "scipy", "sklearn",
          "plt", "matplotlib", "cv2", "PIL", "Image"]
}

/**
 * LLM call argument sink (identical to BackwardFromLlmInputV2).
 */
class LlmCallArgSink extends DataFlow::Node {
  LlmCallArgSink() {
    // PATTERN 1: OpenAI-style method calls .create(), .acreate()
    exists(Call call |
      this.asExpr() = call.getAnArg() and
      exists(Attribute attr |
        attr = call.getFunc() and
        attr.getName() = ["create", "acreate"]
      )
    )
    or
    // PATTERN 2: Chain/model methods with exclusion
    exists(Call call |
      this.asExpr() = call.getAnArg() and
      exists(Attribute attr |
        attr = call.getFunc() and
        attr.getName() = ["invoke", "run", "predict", "generate", "start",
                          "complete", "call", "ask", "query", "send",
                          "promptChatCompletion", "interactive_completion",
                          "create_chat_completion", "generate_text",
                          "chat_completion", "gpt_completion",
                          "llm_call", "get_completion", "get_response",
                          "send_prompt"] and
        not exists(string objName |
          attr.getObject().(Name).getId() = objName and
          isExcludedObject(objName)
        )
      )
    )
    or
    // PATTERN 3: Bare function calls -- LLM-specific names
    exists(Call call |
      this.asExpr() = call.getAnArg() and
      exists(Name func |
        func = call.getFunc() and
        func.getId() = [
          "generate", "acompletion", "completion",
          "openai_call", "llm_completion", "chat_completion", "chat",
          "llm", "llm_call",
          "call_openai_api", "fetch_chat", "query_llm", "call_llm",
          "get_completion", "get_response", "send_prompt",
          "openai_call", "call_openai_model", "gpt_completion",
          "completions_with_backoff", "chat_completions_with_backoff",
          "guidance", "llm_classify"
        ]
      )
    )
    or
    // PATTERN 4: Callable LLM objects
    exists(Call call |
      this.asExpr() = call.getAnArg() and
      exists(Name func |
        func = call.getFunc() and
        func.getId() = ["llm", "model", "chat_model", "language_model",
                        "ai", "chatbot", "bot", "gpt", "claude",
                        "chain", "agent", "pipeline"]
      )
    )
    or
    // PATTERN 5: self.model(x), self.llm(x), etc.
    exists(Call call |
      this.asExpr() = call.getAnArg() and
      exists(Attribute attr |
        attr = call.getFunc() and
        attr.getName() = ["model", "llm", "chain", "llm_model", "chat_model",
                          "language_model", "ai", "chatbot", "gpt", "client",
                          "openai", "anthropic", "llm_chain", "qa_chain"]
      )
    )
    or
    // PATTERN 6: Keyword arguments on known LLM method calls
    exists(Call call, Keyword kw |
      kw = call.getAKeyword() and
      kw.getArg() = ["prompt", "messages", "input", "content", "query",
                      "text", "question", "instruction", "context",
                      "system_message", "user_message", "template",
                      "prompt_text", "input_text"] and
      this.asExpr() = kw.getValue() and
      (
        exists(Attribute attr |
          attr = call.getFunc() and
          attr.getName() = ["create", "acreate", "invoke", "run", "predict",
                            "generate", "complete", "start", "call",
                            "ask", "query", "send",
                            "promptChatCompletion", "interactive_completion",
                            "create_chat_completion", "generate_text",
                            "chat_completion", "gpt_completion",
                            "llm_call", "get_completion", "get_response",
                            "send_prompt",
                            "model", "llm", "chain"]
        )
        or
        exists(Name func |
          func = call.getFunc() and
          func.getId() = ["generate", "acompletion", "completion",
                          "openai_call", "chat_completion", "chat", "llm",
                          "llm_call", "call_openai_api", "fetch_chat",
                          "query_llm", "call_llm", "get_completion",
                          "get_response", "send_prompt", "call_openai_model",
                          "gpt_completion", "completions_with_backoff",
                          "chat_completions_with_backoff",
                          "guidance", "llm_classify",
                          "model", "chain", "agent", "pipeline"]
        )
      )
    )
    or
    // PATTERN 7: LangChain constructors and chain builders
    exists(Call call, Keyword kw |
      (
        call.getFunc().(Name).getId() = ["LLMChain", "ConversationalRetrievalChain",
                                          "RetrievalQA", "PromptTemplate",
                                          "ChatPromptTemplate", "FewShotPromptTemplate",
                                          "ConversationChain", "AgentExecutor",
                                          "StuffDocumentsChain", "MapReduceDocumentsChain",
                                          "SequentialChain", "SimpleSequentialChain",
                                          "TransformChain", "LLMRouterChain",
                                          "MultiPromptChain", "RouterChain",
                                          "HumanMessage", "SystemMessage", "AIMessage",
                                          "ChatOpenAI", "OpenAI", "OpenAIChat",
                                          "Anthropic", "HuggingFaceHub",
                                          "ChatAnthropic", "AzureChatOpenAI"]
        or
        exists(Attribute attr |
          attr = call.getFunc() and
          attr.getName() = ["from_llm", "from_chain_type", "from_template",
                            "from_messages", "from_examples"]
        )
      ) and
      kw = call.getAKeyword() and
      kw.getArg() = ["prompt", "template", "prefix", "suffix",
                      "input_variables", "examples", "partial_variables",
                      "llm", "model", "combine_prompt", "question_prompt",
                      "refine_prompt", "content", "messages",
                      "condense_question_prompt", "system_message"] and
      this.asExpr() = kw.getValue()
    )
    or
    // PATTERN 8: LangChain constructors -- positional args
    exists(Call call |
      this.asExpr() = call.getAnArg() and
      (
        call.getFunc().(Name).getId() = ["HumanMessage", "SystemMessage", "AIMessage",
                                          "HumanMessagePromptTemplate",
                                          "SystemMessagePromptTemplate"]
        or
        exists(Attribute attr |
          attr = call.getFunc() and
          attr.getName() = ["from_llm", "from_chain_type", "from_template",
                            "from_messages", "from_examples"]
        )
      )
    )
    or
    // PATTERN 9: guidance framework
    exists(Call call |
      this.asExpr() = call.getAnArg() and
      call.getFunc().(Name).getId() = "guidance"
    )
    or
    exists(Call call, Keyword kw |
      call.getFunc().(Name).getId() = "guidance" and
      kw = call.getAKeyword() and
      this.asExpr() = kw.getValue()
    )
    or
    // PATTERN 10: Broader .create() with keyword args
    exists(Call call, Keyword kw |
      exists(Attribute attr |
        attr = call.getFunc() and
        attr.getName() = "create" and
        not exists(string objName |
          attr.getObject().(Name).getId() = objName and
          isExcludedObject(objName)
        )
      ) and
      kw = call.getAKeyword() and
      kw.getArg() = ["prompt", "messages", "input", "content",
                      "model", "engine"] and
      this.asExpr() = kw.getValue()
    )
    or
    // PATTERN 11: Static method calls .call, .generate, etc.
    exists(Call call |
      this.asExpr() = call.getAnArg() and
      exists(Attribute attr |
        attr = call.getFunc() and
        attr.getName() = ["call", "generate", "complete", "create",
                          "chat_completion", "completions"]
      )
    )
    or
    // PATTERN 12: Keyword 'prompt' or 'messages' on ANY call
    exists(Call call, Keyword kw |
      kw = call.getAKeyword() and
      kw.getArg() = ["prompt", "messages"] and
      this.asExpr() = kw.getValue() and
      not exists(Attribute attr, string objName |
        attr = call.getFunc() and
        attr.getObject().(Name).getId() = objName and
        isExcludedObject(objName)
      )
    )
  }
}

// =============================================
// Part A: Data-flow backward slice (taint tracking)
// =============================================
module FullBackwardConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(source.asExpr())
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof LlmCallArgSink
  }
}

module FullBackwardFlow = TaintTracking::Global<FullBackwardConfig>;

// =============================================
// Part B: Control dependency -- conditions that guard data-slice nodes
// =============================================

/**
 * A statement S is control-dependent on condition C if S is nested inside
 * an If/For/While/With/Try block whose test/iterator/context is C.
 * We walk up the AST via getParentNode+() to find enclosing control structures.
 */
predicate controlDependencyExpr(Stmt controlled, Expr condition) {
  // If statement: body and orelse are control-dependent on test
  exists(If ifStmt |
    controlled.getParentNode+() = ifStmt and
    controlled != ifStmt and
    condition = ifStmt.getTest()
  )
  or
  // While statement: body is control-dependent on test
  exists(While whileStmt |
    controlled.getParentNode+() = whileStmt and
    controlled != whileStmt and
    condition = whileStmt.getTest()
  )
  or
  // For statement: body is control-dependent on iterator
  exists(For forStmt |
    controlled.getParentNode+() = forStmt and
    controlled != forStmt and
    condition = forStmt.getIter()
  )
}

/**
 * Get the enclosing statement for an expression.
 */
Stmt enclosingStmt(Expr e) {
  result = e.getParentNode+() and
  result instanceof Stmt
}

from DataFlow::Node node, string label
where
  // Part A: data-flow nodes in the backward slice
  (
    exists(LlmCallArgSink sink |
      FullBackwardFlow::flow(node, sink)
    ) and
    label = node.getLocation().getFile().getBaseName() + ":" +
            node.getLocation().getStartLine().toString() + " [data]"
  )
  or
  // Part B: control-dependency conditions that guard data-slice nodes
  (
    exists(DataFlow::Node dataNode, LlmCallArgSink sink, Expr cond, Stmt controlled |
      FullBackwardFlow::flow(dataNode, sink) and
      enclosingStmt(dataNode.asExpr()) = controlled and
      controlDependencyExpr(controlled, cond) and
      node.asExpr() = cond and
      // Ensure same file
      node.getLocation().getFile() = dataNode.getLocation().getFile()
    ) and
    label = node.getLocation().getFile().getBaseName() + ":" +
            node.getLocation().getStartLine().toString() + " [control]"
  )
select node, label
