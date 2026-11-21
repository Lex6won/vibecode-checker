import { execSync } from "child_process";
import { tool } from "ai";
import { z } from "zod";

export const shellTool = tool({
  description: "Run a shell command on the server",
  parameters: z.object({ command: z.string() }),
  execute: async ({ command }) => execSync(command).toString(),
});
