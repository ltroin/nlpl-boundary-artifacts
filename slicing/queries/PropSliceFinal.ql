/**
 * @name Prop-only backward slice (data + control) from LLM call arguments
 * @description Computes a backward slice including both data dependencies
 *              (via taint tracking) and control dependencies (enclosing
 *              if/for/while/with/try conditions) from LLM API call arguments.
 *              No barriers applied.
 * @kind problem
 * @problem.severity recommendation
 * @id llm-boundary/prop-slice-final
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
module PropBackwardConfig implements DataFlow::ConfigSig {
  predicate isBarrier(DataFlow::Node node) {
    exists(Name n | n = node.asExpr() |
    (n.getId() = "AI_PROMPT" and n.getLocation().getFile().getBaseName() = "1712n__dn-institute__tools_claude_retriever_client.py") or
    (n.getId() = "HUMAN_PROMPT" and n.getLocation().getFile().getBaseName() = "1712n__dn-institute__tools_claude_retriever_client.py") or
    (n.getId() = "description" and n.getLocation().getFile().getBaseName() = "1712n__dn-institute__tools_claude_retriever_client.py") or
    (n.getId() = "query" and n.getLocation().getFile().getBaseName() = "1712n__dn-institute__tools_claude_retriever_client.py") or
    (n.getId() = "context_length" and n.getLocation().getFile().getBaseName() = "Arize-ai__LLMTest_NeedleInAHaystack__LLMNeedleHaystackTester.py") or
    (n.getId() = "depth_percent" and n.getLocation().getFile().getBaseName() = "Arize-ai__LLMTest_NeedleInAHaystack__LLMNeedleHaystackTester.py") or
    (n.getId() = "generate_context" and n.getLocation().getFile().getBaseName() = "Arize-ai__LLMTest_NeedleInAHaystack__LLMNeedleHaystackTester.py") or
    (n.getId() = "needle" and n.getLocation().getFile().getBaseName() = "Arize-ai__LLMTest_NeedleInAHaystack__LLMNeedleHaystackTester.py") or
    (n.getId() = "random_city" and n.getLocation().getFile().getBaseName() = "Arize-ai__LLMTest_NeedleInAHaystack__LLMNeedleHaystackTester.py") or
    (n.getId() = "retrieval_question" and n.getLocation().getFile().getBaseName() = "Arize-ai__LLMTest_NeedleInAHaystack__LLMNeedleHaystackTester.py") or
    (n.getId() = "trim_context" and n.getLocation().getFile().getBaseName() = "Arize-ai__LLMTest_NeedleInAHaystack__LLMNeedleHaystackTester.py") or
    (n.getId() = "capabilities" and n.getLocation().getFile().getBaseName() = "DaemonIB__GPT-HTN-Planner__src_gpt4_utils.py") or
    (n.getId() = "agent_scratchpad" and n.getLocation().getFile().getBaseName() = "Dataherald__dataherald__dataherald_sql_generator_dataherald_sqlagent.py") or
    (n.getId() = "query" and n.getLocation().getFile().getBaseName() = "Elliott-Chong__Dionysuss__backend_assembly.py") or
    (n.getId() = "user_role_name" and n.getLocation().getFile().getBaseName() = "IntelligenzaArtificiale__Free-Auto-GPT__Camel.py") or
    (n.getId() = "objective" and n.getLocation().getFile().getBaseName() = "JayZeeDesign__inbox-manager-agent__custom_tools.py") or
    (n.getId() = "description" and n.getLocation().getFile().getBaseName() = "Paillat-dev__FABLE__generators_thumbnail.py") or
    (n.getId() = "context" and n.getLocation().getFile().getBaseName() = "SooLab__DDCOT__rationale_generation.py") or
    (n.getId() = "has_image" and n.getLocation().getFile().getBaseName() = "SooLab__DDCOT__rationale_generation.py") or
    (n.getId() = "objective" and n.getLocation().getFile().getBaseName() = "Xyntopia__pydoxtools__pydoxtools_extract_nlpchat.py") or
    (n.getId() = "previous_tasks" and n.getLocation().getFile().getBaseName() = "Xyntopia__pydoxtools__pydoxtools_extract_nlpchat.py") or
    (n.getId() = "bounding_box" and n.getLocation().getFile().getBaseName() = "Yuqifan1117__HalluciDoctor__utils_prompt_generation.py") or
    (n.getId() = "gen_text" and n.getLocation().getFile().getBaseName() = "allenai__openpi-dataset__v2.0_source_predict_salience.py") or
    (n.getId() = "inputs" and n.getLocation().getFile().getBaseName() = "amosjyng__langchain-contrib__langchain_contrib_tools_terminal_safety.py") or
    (n.getId() = "question_prefix" and n.getLocation().getFile().getBaseName() = "anshitag__memit_csk__memit_csk_dataset_script_data_creation_prompts.py") or
    (n.getId() = "args" and n.getLocation().getFile().getBaseName() = "biobootloader__wolverine__wolverine_wolverine.py") or
    (n.getId() = "news_number" and n.getLocation().getFile().getBaseName() = "c2siorg__b0bot__services_NewsService.py") or
    (n.getId() = "INSTRUCTIONAL_PROMPT" and n.getLocation().getFile().getBaseName() = "cannlytics__cannlytics__cannlytics_data_strains_strains_ai.py") or
    (n.getId() = "raw_desc_prompt" and n.getLocation().getFile().getBaseName() = "deepset-ai__biqa-llm__sql_generation.py") or
    (n.getId() = "enhancement_system_prompt" and n.getLocation().getFile().getBaseName() = "dgarnitz__vectorflow__client_src_vectorflow_client_chunk_enhancer.py") or
    (n.getId() = "message" and n.getLocation().getFile().getBaseName() = "elebumm__YouTubeAIExtension__endpoint_utils_database.py") or
    (n.getId() = "explicit_persona_str" and n.getLocation().getFile().getBaseName() = "eujhwang__personalized-llms__personalized_opinionqa_personalized_opinionqa.py") or
    (n.getId() = "topic" and n.getLocation().getFile().getBaseName() = "eujhwang__personalized-llms__personalized_opinionqa_personalized_opinionqa.py") or
    (n.getId() = "language" and n.getLocation().getFile().getBaseName() = "format81__TI-Mindmap-GPT__timindmapgpt.py") or
    (n.getId() = "bad_response" and n.getLocation().getFile().getBaseName() = "huangjia2019__langchain__07_%E8%A7%A3%E6%9E%90%E8%BE%93%E5%87%BA_03_RetryParser.py") or
    (n.getId() = "choice1" and n.getLocation().getFile().getBaseName() = "idavidrein__gpqa__baselines_utils.py") or
    (n.getId() = "choice2" and n.getLocation().getFile().getBaseName() = "idavidrein__gpqa__baselines_utils.py") or
    (n.getId() = "choice4" and n.getLocation().getFile().getBaseName() = "idavidrein__gpqa__baselines_utils.py") or
    (n.getId() = "instruction_hint" and n.getLocation().getFile().getBaseName() = "jina-ai__thinkgpt__thinkgpt_infer.py") or
    (n.getId() = "action" and n.getLocation().getFile().getBaseName() = "jonathanmli__Avalon-LLM__Search_dynamics.py") or
    (n.getId() = "notes" and n.getLocation().getFile().getBaseName() = "jonathanmli__Avalon-LLM__Search_dynamics.py") or
    (n.getId() = "state" and n.getLocation().getFile().getBaseName() = "jonathanmli__Avalon-LLM__Search_dynamics.py") or
    (n.getId() = "data" and n.getLocation().getFile().getBaseName() = "jxnl__instructor__examples_classification_simple_prediction.py") or
    (n.getId() = "title" and n.getLocation().getFile().getBaseName() = "kenoharada__AI-LaBuddy__summarizer_make_lecture_notes.py") or
    (n.getId() = "temperature" and n.getLocation().getFile().getBaseName() = "kyegomez__swarms__playground_demos_autotemp_autotemp.py") or
    (n.getId() = "template_1_pretty" and n.getLocation().getFile().getBaseName() = "langchain-ai__prompt-eval-recommendation__eval_suggestions.py") or
    (n.getId() = "big_message" and n.getLocation().getFile().getBaseName() = "langroid__langroid__tests_main_test_llm.py") or
    (n.getId() = "current_file_path" and n.getLocation().getFile().getBaseName() = "modal-labs__devlooper__src_prompts.py") or
    (n.getId() = "package_manager" and n.getLocation().getFile().getBaseName() = "modal-labs__devlooper__src_prompts.py") or
    (n.getId() = "test_command" and n.getLocation().getFile().getBaseName() = "modal-labs__devlooper__src_prompts.py") or
    (n.getId() = "criterion" and n.getLocation().getFile().getBaseName() = "montemac__activation_additions__activation_additions_metrics.py") or
    (n.getId() = "title" and n.getLocation().getFile().getBaseName() = "montemac__activation_additions__activation_additions_metrics.py") or
    (n.getId() = "thoughts" and n.getLocation().getFile().getBaseName() = "ngaut__jarvis__experiments_react.py") or
    (n.getId() = "examples" and n.getLocation().getFile().getBaseName() = "nicknochnack__Nopenai__app-comparison.py") or
    (n.getId() = "now" and n.getLocation().getFile().getBaseName() = "parea-ai__parea-sdk-py__parea_cookbook_tracing_with_open_ai_endpoint_directly.py") or
    (n.getId() = "strftime" and n.getLocation().getFile().getBaseName() = "parea-ai__parea-sdk-py__parea_cookbook_tracing_with_open_ai_endpoint_directly.py") or
    (n.getId() = "tgt_lang" and n.getLocation().getFile().getBaseName() = "pigeonai-org__ViDove__src_srt_util_srt.py") or
    (n.getId() = "history" and n.getLocation().getFile().getBaseName() = "pinecone-io__genqa-rag-demo__streamlit_app_todo-splade_Snowflake_app_local.py") or
    (n.getId() = "ExecutedTaskParser" and n.getLocation().getFile().getBaseName() = "saten-private__BabyCommandAGI__babyagi.py") or
    (n.getId() = "command" and n.getLocation().getFile().getBaseName() = "saten-private__BabyCommandAGI__babyagi.py") or
    (n.getId() = "current_dir" and n.getLocation().getFile().getBaseName() = "saten-private__BabyCommandAGI__babyagi.py") or
    (n.getId() = "executed_task_list" and n.getLocation().getFile().getBaseName() = "saten-private__BabyCommandAGI__babyagi.py") or
    (n.getId() = "article_description" and n.getLocation().getFile().getBaseName() = "seedgularity__AIBlogPilotGPT__articles_writing.py") or
    (n.getId() = "func_a" and n.getLocation().getFile().getBaseName() = "shreyashankar__spade-experiments__spade_v3_check_subsumes.py") or
    (n.getId() = "func_b" and n.getLocation().getFile().getBaseName() = "shreyashankar__spade-experiments__spade_v3_check_subsumes.py") or
    (n.getId() = "prompt_template" and n.getLocation().getFile().getBaseName() = "shreyashankar__spade-experiments__spade_v3_check_subsumes.py") or
    (n.getId() = "response" and n.getLocation().getFile().getBaseName() = "shreyashankar__spade-experiments__spade_v3_check_subsumes.py") or
    (n.getId() = "filename" and n.getLocation().getFile().getBaseName() = "sydowma__codeGPT__analysis_repository.py") or
    (n.getId() = "best" and n.getLocation().getFile().getBaseName() = "tshu-w__DBCopilot__src_utils_text2sql.py") or
    (n.getId() = "default_system_prompt" and n.getLocation().getFile().getBaseName() = "tshu-w__DBCopilot__src_utils_text2sql.py") or
    (n.getId() = "llm" and n.getLocation().getFile().getBaseName() = "tshu-w__DBCopilot__src_utils_text2sql.py") or
    (n.getId() = "AI_PROMPT" and n.getLocation().getFile().getBaseName() = "ttwj__open-carbon-viz__fetch_and_rate.py") or
    (n.getId() = "HUMAN_PROMPT" and n.getLocation().getFile().getBaseName() = "ttwj__open-carbon-viz__fetch_and_rate.py") or
    (n.getId() = "_get_examples" and n.getLocation().getFile().getBaseName() = "uber__piranha__experimental_piranha_playground_rule_inference_piranha_chat.py") or
    (n.getId() = "current_summary" and n.getLocation().getFile().getBaseName() = "weaviate__weaviate-podcast-search__generative-feedback-loops_full-pod-summary.py") or
    (n.getId() = "AI_PROMPT" and n.getLocation().getFile().getBaseName() = "wenhuchen__TheoremQA__run_claude.py") or
    (n.getId() = "HUMAN_PROMPT" and n.getLocation().getFile().getBaseName() = "wenhuchen__TheoremQA__run_claude.py") or
    (n.getId() = "os_version" and n.getLocation().getFile().getBaseName() = "yoheinakajima__babyagi__babycoder_babycoder.py") or
    (n.getId() = "notes" and n.getLocation().getFile().getBaseName() = "yoheinakajima__babyagi__classic_BabyCatAGI.py") or
    (n.getId() = "websearch_var" and n.getLocation().getFile().getBaseName() = "yoheinakajima__babyagi__classic_BabyCatAGI.py") or
    (n.getId() = "example_params" and n.getLocation().getFile().getBaseName() = "yoheinakajima__babyagi__classic_BabyElfAGI_skills_code_reader.py") or
    (n.getId() = "example_response" and n.getLocation().getFile().getBaseName() = "yoheinakajima__babyagi__classic_BabyElfAGI_skills_code_reader.py") or
    (n.getId() = "job_desc_keys" and n.getLocation().getFile().getBaseName() = "yusuf-wadi__autoApply__AutoApplier.py")
    )
  }

  predicate isSource(DataFlow::Node source) {
    exists(source.asExpr())
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof LlmCallArgSink
  }
}

module PropBackwardFlow = TaintTracking::Global<PropBackwardConfig>;

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
      PropBackwardFlow::flow(node, sink)
    ) and
    label = node.getLocation().getFile().getBaseName() + ":" +
            node.getLocation().getStartLine().toString() + " [data]"
  )
  or
  // Part B: control-dependency conditions that guard data-slice nodes
  (
    exists(DataFlow::Node dataNode, LlmCallArgSink sink, Expr cond, Stmt controlled |
      PropBackwardFlow::flow(dataNode, sink) and
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
