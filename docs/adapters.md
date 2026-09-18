# Using sluice with an existing agent

Monitor mode ships two integration styles for each provider.

## 1. Drop-in guard (keep your loop)

Wrap the SDK client. The call signature and return type are unchanged; tool calls that
violate policy are removed from the response and replaced by a text notice.

```python
import anthropic
from sluice.monitor import Monitor
from sluice.monitor.adapters.anthropic import guard_anthropic
from sluice.policy import Policy

monitor = Monitor(Policy.load("policy.yaml"), registry)
client = guard_anthropic(anthropic.Anthropic(), monitor)
resp = client.messages.create(model="claude-sonnet-5", max_tokens=1024,
                              tools=tools, messages=messages)
# resp.content never contains a blocked tool_use block
```

| provider                     | wrapper          | guarded method                  |
|------------------------------|------------------|---------------------------------|
| Anthropic                    | `guard_anthropic`| `client.messages.create`        |
| OpenAI-compatible (OpenAI, vLLM, LM Studio, OpenRouter) | `guard_openai` | `client.chat.completions.create` |
| Ollama                       | `guard_ollama`   | `client.chat`                   |

On every request the guard labels anything new in `messages`: system and user text by their
source classes, and tool results by the tool's source class joined with the labels of the
arguments that produced them. Pass `raise_on_block=True` to get a `SluiceBlocked`
exception instead of a rewritten response. Streaming (`stream=True`) is refused; see
DECISIONS D13.

Tool names in the response must be registered in the `ToolRegistry`; an unknown tool is
blocked.

## 2. sluice's own loop

```python
from sluice.agent import Agent
from sluice.monitor.adapters.openai import OpenAILLM

agent = Agent(OpenAILLM(openai.OpenAI(), "gpt-5"), registry, monitor)
result = agent.run("Summarize my inbox")
```

`AnthropicLLM`, `OpenAILLM` and `OllamaLLM` implement the same `LLMClient` protocol as the
test suite's `MockLLM`.

## MCP tools

```python
from anyio.from_thread import start_blocking_portal
from sluice.tools import COMMS, FS_READ
from sluice.tools.mcp import list_all_tools, portal_caller, register_mcp_tools

with start_blocking_portal() as portal:
    tools = portal.call(list_all_tools, session)          # an mcp.ClientSession
    register_mcp_tools(registry, tools, portal_caller(portal, session), server="files",
                       caps={"read_file": [FS_READ], "send": [COMMS]})
```

Name each tool's output in the policy as `mcp.<server>.<tool>`; unnamed ones fail closed.

## Approvals (`on_violation: ask`)

`sluice.monitor.ask.rich_ask()` shows the explanation and asks y/N on a TTY. Without a TTY,
or on EOF / Ctrl-C, the call is blocked.

## Replay and what-if

```
sluice replay sluice-out/inbox-assistant/trace.jsonl --graph replay.html
sluice replay trace.jsonl --policy stricter.yaml     # which decisions would change?
```

## Trifecta check in CI

```
sluice trifecta examples/inbox-assistant --strict    # exit 1 on an unguarded exfil path
```
