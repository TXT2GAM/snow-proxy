/**
 * OpenAI 兼容的 Snowflake Cortex 代理（Deno TypeScript 版本）
 *
 * - 支持 /v1/models 与 /v1/chat/completions（流式与非流式）
 * - 兼容 OpenAI tools（function calling）到 Snowflake Cortex 工具规范的转换
 * - 将 Snowflake SSE 块转换为 OpenAI Chat Completions chunk
 *
 * 鉴权方式:
 * 直接传入账号信息：Authorization: Bearer <identifier>:<account_token>
 * 例如：Authorization: Bearer FHEYMUX-DQB97617:eyJraWQiOiI3MjAxMzUzMzE4OSIsImFsZyI6IkVTMjU2In0...
 */

import { Application, Router } from "https://deno.land/x/oak@v12.6.0/mod.ts";
import { oakCors } from "https://deno.land/x/cors@v1.2.2/mod.ts";

// 类型定义
interface StreamState {
  nextToolIndex: number;
  toolStates: Map<string, {id: string, name?: string, index: number, buffer: string}>;
  lastToolId?: string;
  roleEmitted: boolean;
  sawToolUse: boolean;
}

interface OpenAITool {
  type: "function";
  function: {
    name: string;
    description?: string;
    parameters?: {
      type: "object";
      properties: Record<string, any>;
      required?: string[];
    };
  };
}

interface CortexTool {
  tool_spec: {
    type: "generic";
    name: string;
    description: string;
    input_schema: {
      type: "object";
      properties: Record<string, any>;
      required: string[];
    };
  };
}

interface AuthResult {
  identifier: string;
  account_token: string;
}


// 预定义的模型响应
const MODELS_RESPONSE = {
  "data": [
    {"created": 1758960243, "id": "claude-3-5-sonnet", "object": "model", "owned_by": "anthropic"},
    {"created": 1758960243, "id": "claude-3-7-sonnet", "object": "model", "owned_by": "anthropic"},
    {"created": 1758960243, "id": "claude-4-sonnet", "object": "model", "owned_by": "anthropic"},
    {"created": 1758960243, "id": "claude-sonnet-4-5", "object": "model", "owned_by": "anthropic"},
    {"created": 1758960243, "id": "openai-gpt-5-chat", "object": "model", "owned_by": "openai"},
    {"created": 1758960243, "id": "openai-gpt-5", "object": "model", "owned_by": "openai"},
    {"created": 1758960243, "id": "openai-gpt-5-mini", "object": "model", "owned_by": "openai"},
    {"created": 1758960243, "id": "openai-gpt-5-nano", "object": "model", "owned_by": "openai"}
  ],
  "object": "list"
};

/**
 * 规范工具参数增量为字符串片段
 */
function normalizeToolArg(input: any): string {
  if (input === undefined || input === null) return "";
  return typeof input === "string" ? input : JSON.stringify(input);
}

/**
 * 校验最简工具定义格式
 */
function validateBasicTools(tools: any[]): boolean {
  if (!Array.isArray(tools)) return false;
  if (tools.length === 0) return false;

  for (const tool of tools) {
    if (!tool || typeof tool !== 'object') return false;
    if (tool.type !== 'function') return false;
    if (!tool.function || !tool.function.name) return false;
  }

  return true;
}

/**
 * 将 OpenAI 的 tools 定义转换为 Cortex 工具规范
 */
function convertOpenAIToolsToCortex(openaiTools: OpenAITool[]): CortexTool[] {
  console.log("Converting OpenAI tools to Cortex format");

  return openaiTools.map(tool => {
    const func = tool.function;

    const cortexTool: CortexTool = {
      tool_spec: {
        type: "generic",
        name: func.name,
        description: func.description || "",
        input_schema: {
          type: "object",
          properties: (func.parameters && func.parameters.properties) || {},
          required: (func.parameters && func.parameters.required) || []
        }
      }
    };

    return cortexTool;
  });
}

/**
 * 将 OpenAI 的 tool_choice 转为 Cortex 的 tool_choice
 */
function convertOpenAIToolChoiceToCortex(openaiToolChoice?: string | object): object {
  if (!openaiToolChoice || openaiToolChoice === "auto") {
    return { type: "auto" };
  }

  if (openaiToolChoice === "none") {
    return { type: "none" };
  }

  if (openaiToolChoice === "required") {
    return { type: "required" };
  }

  // 特定函数选择
  if (typeof openaiToolChoice === "object" && (openaiToolChoice as any).type === "function") {
    return {
      type: "tool",
      name: [(openaiToolChoice as any).function.name]
    };
  }

  return { type: "auto" };
}

/**
 * 构建工具调用ID到工具名称的映射
 */
function buildToolCallMapping(messages: any[]): Map<string, string> {
  const toolCallMap = new Map<string, string>();

  for (const message of messages) {
    if (message.role === "assistant" && message.tool_calls) {
      for (const toolCall of message.tool_calls) {
        toolCallMap.set(toolCall.id, toolCall.function.name);
      }
    }
  }

  return toolCallMap;
}

/**
 * 判断消息是否是可合并类型
 */
function shouldMergeMessage(message: any): boolean {
  if (!message.content_list || !Array.isArray(message.content_list)) {
    return false;
  }

  const types = message.content_list.map((item: any) => item.type);
  const uniqueTypes = [...new Set(types)];

  return uniqueTypes.length === 1 &&
    (uniqueTypes[0] === 'tool_results' || uniqueTypes[0] === 'tool_use');
}

/**
 * 判断两个消息是否可以合并
 */
function canMergeWith(message1: any, message2: any): boolean {
  if (message1.role !== message2.role) {
    return false;
  }

  if (!shouldMergeMessage(message1) || !shouldMergeMessage(message2)) {
    return false;
  }

  const type1 = message1.content_list[0]?.type;
  const type2 = message2.content_list[0]?.type;

  return type1 === type2;
}

/**
 * 重新整理 tool_results，让它们紧跟对应的 tool_use
 */
function reorganizeToolResults(messages: any[]): any[] {
  const result: any[] = [];
  const toolResultsMap = new Map<string, any>();

  // 收集所有的 tool_results 内容
  for (const message of messages) {
    if (message.content_list && Array.isArray(message.content_list)) {
      for (const content of message.content_list) {
        if (content.type === 'tool_results' && content.tool_results?.tool_use_id) {
          toolResultsMap.set(content.tool_results.tool_use_id, content);
        }
      }
    }
  }

  // 处理消息，将 tool_results 重新组织
  for (const message of messages) {
    if (message.content_list && Array.isArray(message.content_list)) {
      const hasToolUse = message.content_list.some((content: any) => content.type === 'tool_use');
      const hasToolResults = message.content_list.some((content: any) => content.type === 'tool_results');

      if (hasToolResults && !hasToolUse) {
        continue;
      }

      if (hasToolUse) {
        result.push(message);

        const correspondingToolResults: any[] = [];
        let toolResultRole = 'user';

        for (const content of message.content_list) {
          if (content.type === 'tool_use' && content.tool_use?.tool_use_id) {
            const toolResult = toolResultsMap.get(content.tool_use.tool_use_id);
            if (toolResult) {
              correspondingToolResults.push(toolResult);
            }
          }
        }

        if (correspondingToolResults.length > 0) {
          for (const originalMessage of messages) {
            if (originalMessage.content_list && Array.isArray(originalMessage.content_list)) {
              const hasMatchingToolResult = originalMessage.content_list.some((content: any) =>
                content.type === 'tool_results' &&
                correspondingToolResults.some(tr => tr.tool_results?.tool_use_id === content.tool_results?.tool_use_id)
              );
              if (hasMatchingToolResult) {
                toolResultRole = originalMessage.role;
                break;
              }
            }
          }

          result.push({
            role: toolResultRole,
            content_list: correspondingToolResults
          });
        }
      } else {
        result.push(message);
      }
    } else {
      result.push(message);
    }
  }

  return result;
}

/**
 * 合并相邻的同类型消息
 */
function mergeAdjacentMessages(messages: any[]): any[] {
  const merged: any[] = [];
  let i = 0;

  while (i < messages.length) {
    const currentMessage = messages[i];

    if (shouldMergeMessage(currentMessage)) {
      const mergedMessage = { ...currentMessage };
      const contentList = [...(currentMessage.content_list || [])];

      let j = i + 1;
      while (j < messages.length && canMergeWith(currentMessage, messages[j])) {
        contentList.push(...(messages[j].content_list || []));
        j++;
      }

      mergedMessage.content_list = contentList;
      merged.push(mergedMessage);
      i = j;
    } else {
      merged.push(currentMessage);
      i++;
    }
  }

  return reorganizeToolResults(merged);
}

/**
 * 将 OpenAI 格式的消息转换为 Snowflake Cortex 格式
 */
function convertOpenAIMessageToCortex(message: any, toolCallMap?: Map<string, string>): any {
  const role = message.role === "developer" ? "system" : message.role;
  const cortexMessage: any = { role };

  if (role === "assistant" && message.tool_calls) {
    const contentList: any[] = [];

    if (message.content && typeof message.content === "string") {
      cortexMessage.content = message.content;
    }

    for (const toolCall of message.tool_calls) {
      contentList.push({
        type: "tool_use",
        tool_use: {
          tool_use_id: toolCall.id,
          name: toolCall.function.name,
          input: safeJsonParse(toolCall.function.arguments)
        }
      });
    }

    if (contentList.length > 0) {
      cortexMessage.content_list = contentList;
    }

  } else if (message.role === "tool") {
    cortexMessage.role = "user";
    cortexMessage.content_list = [{
      type: "tool_results",
      tool_results: {
        tool_use_id: message.tool_call_id,
        name: (toolCallMap && toolCallMap.get(message.tool_call_id)) || "unknown_tool",
        content: [{
          type: "text",
          text: typeof message.content === "string" ? message.content : convertContentArrayToString(message.content)
        }]
      }
    }];

  } else {
    if (typeof message.content === "string") {
      cortexMessage.content = message.content;
    } else if (Array.isArray(message.content)) {
      cortexMessage.content = convertContentArrayToString(message.content);
    }
  }

  return cortexMessage;
}

/**
 * 更稳妥的 JSON 解析器
 */
function safeJsonParse(s: any): any {
  if (s === undefined || s === null) return {};
  if (typeof s !== "string") return s;
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}

/**
 * 将 content 数组格式转换为简单字符串
 */
function convertContentArrayToString(content: string | any[]): string {
  if (typeof content === 'string') {
    return content;
  }

  if (Array.isArray(content)) {
    const textParts: string[] = [];

    for (const item of content) {
      if (item && typeof item === 'object' && item.type === 'text' && item.text) {
        textParts.push(item.text);
      }
    }

    return textParts.join('\n\n');
  }

  return '';
}

/**
 * 创建从 Snowflake SSE 转换到 OpenAI SSE 的可读流
 */
function createSnowflakeToOpenAIStream(sourceBody: ReadableStream<Uint8Array>, hasTools: boolean, model?: string): ReadableStream<Uint8Array> {
  const state: StreamState = {
    nextToolIndex: 0,
    toolStates: new Map(),
    roleEmitted: false,
    sawToolUse: false
  };

  return new ReadableStream({
    async start(controller) {
      const reader = sourceBody.pipeThrough(new TextDecoderStream()).getReader();
      let hasEmittedFinish = false;

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) {
            if (!hasEmittedFinish) {
              const finishChunk = {
                id: `chatcmpl-${Date.now()}`,
                object: "chat.completion.chunk",
                created: Math.floor(Date.now() / 1000),
                model: model || "unknown",
                choices: [{
                  index: 0,
                  delta: {},
                  finish_reason: state.sawToolUse ? "tool_calls" : "stop"
                }]
              };
              controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(finishChunk)}\n\n`));
            }
            controller.enqueue(new TextEncoder().encode('data: [DONE]\n\n'));
            break;
          }

          const lines = value.split('\n');
          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            const data = line.slice(6).trim();

            if (data === '[DONE]') {
              if (!hasEmittedFinish) {
                const finishChunk = {
                  id: `chatcmpl-${Date.now()}`,
                  object: "chat.completion.chunk",
                  created: Math.floor(Date.now() / 1000),
                  model: model || "unknown",
                  choices: [{
                    index: 0,
                    delta: {},
                    finish_reason: state.sawToolUse ? "tool_calls" : "stop"
                  }]
                };
                controller.enqueue(new TextEncoder().encode(`data: ${JSON.stringify(finishChunk)}\n\n`));
              }
              controller.enqueue(new TextEncoder().encode('data: [DONE]\n\n'));
              return;
            }

            try {
              const parsed = JSON.parse(data);
              const transformed = transformSnowflakeChunk(parsed, state, hasTools, model);
              if (transformed) {
                if (transformed.choices?.[0]?.finish_reason) {
                  hasEmittedFinish = true;
                }
                const outputLine = `data: ${JSON.stringify(transformed)}\n\n`;
                controller.enqueue(new TextEncoder().encode(outputLine));
              }
            } catch {
              // 忽略解析错误行
            }
          }
        }
      } catch (err) {
        controller.error(err);
      } finally {
        controller.close();
      }
    }
  });
}

/**
 * 将 Snowflake 的 SSE 分块转换为 OpenAI Chat Completions chunk
 */
function transformSnowflakeChunk(chunk: any, state: StreamState, hasTools: boolean, model?: string): any {
  const srcChoice = chunk?.choices?.[0];
  const srcDelta = srcChoice?.delta;

  if (srcChoice?.finish_reason) {
    return {
      id: chunk.id || `chatcmpl-${Date.now()}`,
      object: "chat.completion.chunk",
      created: chunk.created || Math.floor(Date.now() / 1000),
      model: model || "unknown",
      choices: [{
        index: 0,
        delta: {},
        finish_reason: srcChoice.finish_reason
      }],
      usage: chunk.usage
    };
  }

  if (chunk?.usage && (!srcDelta || Object.keys(srcDelta).length === 0)) {
    return {
      id: chunk.id || `chatcmpl-${Date.now()}`,
      object: "chat.completion.chunk",
      created: chunk.created || Math.floor(Date.now() / 1000),
      model: model || "unknown",
      choices: [{
        index: 0,
        delta: {},
        finish_reason: state.sawToolUse ? "tool_calls" : "stop"
      }],
      usage: chunk.usage
    };
  }

  if (!srcDelta) {
    return null;
  }

  const outDelta: any = {};

  if (!state.roleEmitted) {
    outDelta.role = "assistant";
    state.roleEmitted = true;
  }

  if (srcDelta.content || srcDelta.text) {
    outDelta.content = srcDelta.content ?? srcDelta.text;
  }

  if (hasTools && srcDelta.type === "tool_use") {
    if (srcDelta.name && srcDelta.tool_use_id) {
      const id = srcDelta.tool_use_id;
      if (!state.toolStates.has(id)) {
        const index = state.nextToolIndex++;
        state.toolStates.set(id, { id, name: srcDelta.name, index, buffer: "" });
      }
      const s = state.toolStates.get(id)!;
      state.lastToolId = id;
      state.sawToolUse = true;

      outDelta.tool_calls = [{
        index: s.index,
        id: s.id,
        type: "function",
        function: {
          name: s.name,
          arguments: ""
        }
      }];
    }

    if (srcDelta.input !== undefined) {
      const id = srcDelta.tool_use_id || state.lastToolId;
      if (id && state.toolStates.has(id)) {
        const s = state.toolStates.get(id)!;
        const piece = normalizeToolArg(srcDelta.input);
        s.buffer += piece;

        outDelta.tool_calls = [{
          index: s.index,
          id: s.id,
          type: "function",
          function: {
            arguments: piece
          }
        }];
      }
    }
  }

  if (Object.keys(outDelta).length === 0) return null;

  return {
    id: chunk.id || `chatcmpl-${Date.now()}`,
    object: "chat.completion.chunk",
    created: chunk.created || Math.floor(Date.now() / 1000),
    model: model || "unknown",
    choices: [{
      index: 0,
      delta: outDelta,
      finish_reason: null
    }]
  };
}

/**
 * 从流式状态聚合最终的 tool_calls
 */
function buildFinalToolCallsFromState(state: StreamState): any[] {
  return Array.from(state.toolStates.values())
    .sort((a, b) => a.index - b.index)
    .map(s => ({
      id: s.id,
      type: "function",
      function: {
        name: s.name ?? "",
        arguments: s.buffer
      }
    }));
}

/**
 * 处理并校验 OpenAI tools
 */
function processToolsRequest(tools: OpenAITool[], tool_choice?: string | object): {cortexTools: CortexTool[], cortexToolChoice: object} {
  console.log("Processing tools request with", tools.length, "tools - v4.0");

  if (!validateBasicTools(tools)) {
    console.log("Tools validation failed");
    throw new Error("Invalid tools format: Each tool must be an object with type 'function' and a function.name property");
  }

  console.log("Tools validation passed - proceeding with Cortex conversion (v4.0)");

  const cortexTools = convertOpenAIToolsToCortex(tools);
  const cortexToolChoice = convertOpenAIToolChoiceToCortex(tool_choice);

  console.log("Converted to Cortex tools:", cortexTools.length);
  console.log("Converted tool_choice:", cortexToolChoice);

  return { cortexTools, cortexToolChoice };
}

/**
 * 校验请求头中的 Authorization: Bearer 并解析账号信息
 * 只支持直接传入账号信息的方式
 */
async function requireKey(ctx: any): Promise<AuthResult> {
  const auth = ctx.request.headers.get("authorization") || "";
  if (!auth.startsWith("Bearer ")) ctx.throw(401, "Missing Authorization header");

  const token = auth.slice(7).trim();

  // 解析 identifier:account_token 格式
  if (token.includes(":")) {
    const colonIndex = token.indexOf(":");
    const identifier = token.substring(0, colonIndex);
    const account_token = token.substring(colonIndex + 1);

    if (identifier && account_token) {
      console.log(`Using account: ${identifier}`);
      return { identifier, account_token };
    }
  }

  ctx.throw(403, "Invalid API key format. Use: identifier:account_token");
}

// 路由设置
const router = new Router();

/**
 * GET /v1/models - 列出可用模型
 */
router.get("/v1/models", (ctx) => {
  ctx.response.body = MODELS_RESPONSE;
});

/**
 * POST /v1/chat/completions - OpenAI 兼容聊天接口
 */
router.post("/v1/chat/completions", async (ctx) => {
  const authResult = await requireKey(ctx);
  const body = await ctx.request.body({ type: "json" }).value;
  const { model, stream = false, messages, tools, tool_choice, ...rest } = body;

  // 验证模型参数是否提供
  if (!model) {
    ctx.response.status = 400;
    ctx.response.headers.set("Content-Type", "application/json");
    ctx.response.body = {
      error: {
        message: "Model is required",
        type: "invalid_request_error",
        code: "MODEL_REQUIRED"
      }
    };
    return;
  }

  const { identifier, account_token } = authResult;

  // 转换消息格式
  const toolCallMap = buildToolCallMapping(messages || []);
  let processedMessages = (messages && messages.map((message: any) => {
    return convertOpenAIMessageToCortex(message, toolCallMap);
  })) || [];

  processedMessages = mergeAdjacentMessages(processedMessages);

  // max_tokens 处理
  let finalMaxTokens = rest.max_tokens;
  if (typeof finalMaxTokens !== 'number' || finalMaxTokens >= 16384) {
    finalMaxTokens = 16384;
  }

  let payload: any;
  const apiEndpoint = `https://${identifier}.snowflakecomputing.com/api/v2/cortex/inference:complete`;

  try {
    if (tools && Array.isArray(tools)) {
      console.log("Processing request with tools:", tools.length);

      try {
        const toolsResult = processToolsRequest(tools, tool_choice);

        if (toolsResult) {
          console.log("Tools request validated, using Cortex tools format");
          payload = {
            model: model,
            messages: processedMessages,
            tools: toolsResult.cortexTools,
            tool_choice: toolsResult.cortexToolChoice,
            ...rest,
            max_tokens: finalMaxTokens
          };
        }
      } catch (toolError) {
        console.error("Tools processing error:", toolError);
        ctx.response.status = 400;
        ctx.response.headers.set("Content-Type", "application/json");
        ctx.response.body = {
          error: {
            message: "Error, please contact admin",
            type: "invalid_request_error",
            code: "REQUEST_ERROR"
          }
        };
        return;
      }
    } else {
      payload = {
        model: model,
        messages: processedMessages,
        ...rest,
        max_tokens: finalMaxTokens
      };
    }
  } catch (error) {
    console.error("Unexpected error in request processing:", error);
    throw error;
  }

  const res = await fetch(apiEndpoint, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${account_token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    console.log("API Endpoint:", apiEndpoint);
    console.log("Request Payload:");
    const payloadForLogging = { ...payload };
    delete payloadForLogging.tools;
    console.log(JSON.stringify(payloadForLogging, null, 2));
    const errorText = await res.text();
    console.log("Error Response:", errorText);
    ctx.throw(res.status, "Error, please contact admin");
  }

  const hasToolsFlag = tools && Array.isArray(tools) && tools.length > 0;

  if (stream) {
    // 流式响应
    ctx.response.status = 200;
    ctx.response.headers.set("Content-Type", "text/event-stream");
    ctx.response.headers.set("Cache-Control", "no-cache");
    ctx.response.headers.set("Connection", "keep-alive");

    if (!res.body) {
      ctx.throw(500, "No response body received");
      return;
    }
    const transformedStream = createSnowflakeToOpenAIStream(res.body, hasToolsFlag, model);
    ctx.response.body = transformedStream;
  } else {
    // 非流式响应
    if (!res.body) {
      ctx.throw(500, "No response body received");
      return;
    }

    let fullContent = "";
    const state: StreamState = {
      nextToolIndex: 0,
      toolStates: new Map(),
      roleEmitted: false,
      sawToolUse: false
    };

    let responseTemplate: any = null;

    try {
      for await (const chunk of res.body.pipeThrough(new TextDecoderStream())) {
        const lines = chunk.split('\n');
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const data = line.slice(6).trim();
          if (data === '[DONE]') break;

          try {
            const parsed = JSON.parse(data);
            const transformed = transformSnowflakeChunk(parsed, state, hasToolsFlag, model);
            if (transformed?.choices?.[0]?.delta) {
              const d = transformed.choices[0].delta;
              if (typeof d.content === "string") fullContent += d.content;
            }
            if (!responseTemplate && parsed?.choices?.[0]) {
              responseTemplate = parsed;
            }
          } catch {
            // 忽略坏行
          }
        }
      }
    } catch (e) {
      console.error("Stream processing error:", e);
    }

    const finalToolCalls = buildFinalToolCallsFromState(state);

    const message: any = {
      role: "assistant",
      content: fullContent || null
    };

    if (finalToolCalls.length > 0) {
      message.tool_calls = finalToolCalls;
      if (!fullContent) {
        message.content = null;
      }
    }

    const openaiResponse = {
      id: (responseTemplate && responseTemplate.id) || `chatcmpl-${Date.now()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model,
      choices: [{
        index: 0,
        message,
        finish_reason: finalToolCalls.length > 0 ? "tool_calls" : "stop"
      }],
      usage: (responseTemplate && responseTemplate.usage) || {
        prompt_tokens: 0,
        completion_tokens: 0,
        total_tokens: 0
      }
    };

    ctx.response.status = 200;
    ctx.response.headers.set("Content-Type", "application/json");
    ctx.response.body = openaiResponse;
  }
});


// 应用设置
const app = new Application();

// 全局日志与错误处理中间件
app.use(async (ctx, next) => {
  const startTime = Date.now();
  const method = ctx.request.method;
  const url = ctx.request.url.pathname;

  console.log(`[${new Date().toISOString()}] ${method} ${url} - Request started`);

  try {
    await next();

    const duration = Date.now() - startTime;
    console.log(`[${new Date().toISOString()}] ${method} ${url} - ${ctx.response.status} (${duration}ms)`);

  } catch (err) {
    const duration = Date.now() - startTime;

    console.error(`[${new Date().toISOString()}] ERROR in ${method} ${url} (${duration}ms):`);
    console.error("Error name:", err.name);
    console.error("Error message:", err.message);
    console.error("Error stack:", err.stack);

    ctx.response.status = err.status || 500;
    ctx.response.headers.set("Content-Type", "application/json");
    ctx.response.body = {
      error: {
        message: "Error, please contact admin",
        type: "server_error",
        code: "INTERNAL_ERROR"
      }
    };
  }
});

app.use(oakCors());
app.use(router.routes());
app.use(router.allowedMethods());

// Deno Deploy 兼容性
if (import.meta.main) {
  const PORT = Number(Deno.env.get("PORT") ?? 8000);
  console.log(`🦕 OpenAI proxy listening on http://localhost:${PORT}`);
  await app.listen({ port: PORT });
}

// 导出 app 用于 Deno Deploy
export default app;
