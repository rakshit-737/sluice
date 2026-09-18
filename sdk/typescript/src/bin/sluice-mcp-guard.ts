#!/usr/bin/env node
/**
 * stdio MCP guard proxy.
 *
 *   sluice-mcp-guard --policy policy.yaml --server files -- npx -y @modelcontextprotocol/server-filesystem /data
 *
 * Everything after `--` is the downstream MCP server command. This process speaks MCP to the
 * client on its own stdio, spawns the server, and pipes newline-delimited JSON-RPC both ways
 * through an McpGuard, answering policy-violating tools/call requests itself.
 */

import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { readFileSync } from "node:fs";
import { Policy } from "../policy.js";
import { McpGuard, type JsonRpcMessage } from "../mcp.js";

interface Args {
  policyPath?: string;
  server: string;
  command: string[];
}

function parseArgs(argv: string[]): Args {
  const out: Args = { server: "mcp", command: [] };
  let i = 0;
  for (; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      out.command = argv.slice(i + 1);
      break;
    } else if (a === "--policy") {
      const v = argv[++i];
      if (v) out.policyPath = v;
    } else if (a === "--server") out.server = argv[++i] ?? "mcp";
  }
  if (out.command.length === 0) throw new Error("no downstream server command after `--`");
  return out;
}

function writeMessage(stream: NodeJS.WritableStream, msg: JsonRpcMessage): void {
  stream.write(JSON.stringify(msg) + "\n");
}

function main(): void {
  const args = parseArgs(process.argv.slice(2));
  const policy = args.policyPath ? Policy.fromYaml(readFileSync(args.policyPath, "utf8")) : Policy.deny();
  const guard = new McpGuard(policy, args.server);

  const child = spawn(args.command[0]!, args.command.slice(1), { stdio: ["pipe", "pipe", "inherit"] });
  child.on("exit", (code) => process.exit(code ?? 0));

  // client (stdin) -> guard -> server (child stdin)
  createInterface({ input: process.stdin }).on("line", (line) => {
    if (!line.trim()) return;
    let msg: JsonRpcMessage;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    const action = guard.fromClient(msg);
    if (action.respond) writeMessage(process.stdout, action.respond);
    if (action.forward) writeMessage(child.stdin, action.forward);
  });

  // server (child stdout) -> guard -> client (stdout)
  createInterface({ input: child.stdout }).on("line", (line) => {
    if (!line.trim()) return;
    let msg: JsonRpcMessage;
    try {
      msg = JSON.parse(line);
    } catch {
      return;
    }
    const action = guard.fromServer(msg);
    if (action.forward) writeMessage(process.stdout, action.forward);
  });
}

main();
