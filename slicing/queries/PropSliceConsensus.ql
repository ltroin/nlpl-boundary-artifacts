/**
 * @name Full backward slice (data + control) from LLM call arguments
 * @description Computes a backward slice including both data dependencies
 *              (via taint tracking) and control dependencies (enclosing
 *              if/for/while/with/try conditions) from LLM API call arguments.
 *              Consensus barriers (expanded): 25 files, 31 Name vars + 7 attribute vars.
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

  predicate isBarrier(DataFlow::Node node) {
    exists(Name n | n = node.asExpr() |
    (n.getId() = "description" and n.getLocation().getFile().getBaseName() = "1712n__dn-institute__tools_claude_retriever_client.py") or
    (n.getId() = "row" and n.getLocation().getFile().getBaseName() = "Arize-ai__LLMTest_NeedleInAHaystack__LLMNeedleHaystackTester.py") or
    (n.getId() = "context_window" and n.getLocation().getFile().getBaseName() = "DaemonIB__GPT-HTN-Planner__src_guidance_prompts_htn_prompts.py") or
    (n.getId() = "prompt" and n.getLocation().getFile().getBaseName() = "EveryOneIsGross__scratchTHOUGHTS__ripYT.py") or
    (n.getId() = "media_file" and n.getLocation().getFile().getBaseName() = "JorisdeJong123__7-Days-of-LangChain__day_2_voice_to_meeting_notes.py") or
    (n.getId() = "sub_q" and n.getLocation().getFile().getBaseName() = "SooLab__DDCOT__rationale_generation.py") or
    (n.getId() = "hallucination_phrases" and n.getLocation().getFile().getBaseName() = "Yuqifan1117__HalluciDoctor__utils_prompt_generation.py") or
    (n.getId() = "top_k" and n.getLocation().getFile().getBaseName() = "aaronlutkowitz2__genai_app_hcls_general__pages_Doctor_Appt_Concierge.py") or
    (n.getId() = "candidate_info" and n.getLocation().getFile().getBaseName() = "agusticonesagago__custom_linkedin_messaging__api_custom_messages.py") or
    (n.getId() = "message" and n.getLocation().getFile().getBaseName() = "elebumm__YouTubeAIExtension__endpoint_utils_database.py") or
    (n.getId() = "country" and n.getLocation().getFile().getBaseName() = "gabrielcassimiro17__async-langchain__sequential_chain.py") or
    (n.getId() = "row" and n.getLocation().getFile().getBaseName() = "gabrielcassimiro17__async-langchain__sequential_chain.py") or
    (n.getId() = "wine_name" and n.getLocation().getFile().getBaseName() = "gabrielcassimiro17__async-langchain__sequential_chain.py") or
    (n.getId() = "query" and n.getLocation().getFile().getBaseName() = "ghif__langchain-tutorial__11-chat-memory.py") or
    (n.getId() = "chat_history" and n.getLocation().getFile().getBaseName() = "gia-guar__JARVIS-ChatGPT__Assistant_research_mode.py") or
    (n.getId() = "function_result" and n.getLocation().getFile().getBaseName() = "hambuger__Andrew__code_util_learn.py") or
    (n.getId() = "get_invoke_method_info_by_name" and n.getLocation().getFile().getBaseName() = "hambuger__Andrew__code_util_learn.py") or
    (n.getId() = "response1" and n.getLocation().getFile().getBaseName() = "hambuger__Andrew__code_util_learn.py") or
    (n.getId() = "axes" and n.getLocation().getFile().getBaseName() = "hyungkwonko__chart-llm__exp_gold_exp_paraphrase.py") or
    (n.getId() = "data" and n.getLocation().getFile().getBaseName() = "jxnl__instructor__examples_classification_simple_prediction.py") or
    (n.getId() = "big_message" and n.getLocation().getFile().getBaseName() = "langroid__langroid__tests_main_test_llm.py") or
    (n.getId() = "query" and n.getLocation().getFile().getBaseName() = "michaelwilliamtang__referral-augment__src_rar_retrievers_query2doc_dense_retriever.py") or
    (n.getId() = "sender_name" and n.getLocation().getFile().getBaseName() = "mominalix__bulk-email-generator-using-ChatGPT__bulk_sales_email_generator.py") or
    (n.getId() = "supporter_info_format" and n.getLocation().getFile().getBaseName() = "morecry__CharacterChat__src_dial_query_data.py") or
    (n.getId() = "supporter_profile" and n.getLocation().getFile().getBaseName() = "morecry__CharacterChat__src_dial_query_data.py") or
    (n.getId() = "tool" and n.getLocation().getFile().getBaseName() = "ngaut__jarvis__experiments_react.py") or
    (n.getId() = "article_title" and n.getLocation().getFile().getBaseName() = "speakerjohnash__Garden-of-Iris__society_bot.py") or
    (n.getId() = "author" and n.getLocation().getFile().getBaseName() = "speakerjohnash__Garden-of-Iris__society_bot.py") or
    (n.getId() = "filename" and n.getLocation().getFile().getBaseName() = "sydowma__codeGPT__analysis_repository.py") or
    (n.getId() = "clips" and n.getLocation().getFile().getBaseName() = "weaviate__weaviate-podcast-search__generative-feedback-loops_auto-chapters.py") or
    (n.getId() = "example_params" and n.getLocation().getFile().getBaseName() = "yoheinakajima__babyagi__classic_BabyElfAGI_skills_code_reader.py")
    )
    or
    exists(Attribute a | a = node.asExpr() |
    (a.getName() = "agent" and a.getObject().(Name).getId() = "self" and a.getLocation().getFile().getBaseName() = "kyegomez__EXA-1__exa_models_AudioGPT_audio-chatgpt.py") or
    (a.getName() = "generate_context" and a.getObject().(Name).getId() = "self" and a.getLocation().getFile().getBaseName() = "Arize-ai__LLMTest_NeedleInAHaystack__LLMNeedleHaystackTester.py") or
    (a.getName() = "news_number" and a.getObject().(Name).getId() = "self" and a.getLocation().getFile().getBaseName() = "c2siorg__b0bot__services_NewsService.py") or
    (a.getName() = "template" and a.getObject().(Name).getId() = "self" and a.getLocation().getFile().getBaseName() = "redwoodresearch__Text-Steganography-Benchmark__textsteg_defenders_llm_defenders.py") or
    (a.getName() = "post_template_suffix" and a.getObject().(Name).getId() = "self" and a.getLocation().getFile().getBaseName() = "redwoodresearch__Text-Steganography-Benchmark__textsteg_defenders_llm_defenders.py") or
    (a.getName() = "promotion" and a.getObject().(Name).getId() = "self" and a.getLocation().getFile().getBaseName() = "sydowma__codeGPT__analysis_repository.py") or
    (a.getName() = "holes" and a.getObject().(Name).getId() = "self" and a.getLocation().getFile().getBaseName() = "uber__piranha__experimental_piranha_playground_rule_inference_piranha_chat.py")
    )
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
