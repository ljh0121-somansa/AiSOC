import * as fs from "node:fs";
import * as path from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function harnessExtension(pi: ExtensionAPI) {
  // // 1. .harness/harness/ 디렉토리 내의 스킬(gemini-reviewer 등)을 pi 스킬로 동적 등록
  // pi.on("resources_discover", async (event, _ctx) => {
  //   const harnessDir = path.join(event.cwd, ".harness", "harness");
  //   if (fs.existsSync(harnessDir)) {
  //     return {
  //       skillPaths: [harnessDir]
  //     };
  //   }
  //   return {};
  // });

  // 2. .harness/harness/*.md 파일들의 내용을 동적으로 읽어 매번 시스템 프롬프트로 로드
  pi.on("before_agent_start", async (event, ctx) => {
    const harnessDir = path.join(ctx.cwd, ".harness", "harness");
    if (!fs.existsSync(harnessDir)) {
      return;
    }

    let appendedPrompt = "";
    try {
      const files = fs.readdirSync(harnessDir);
      for (const file of files) {
        // .md 파일이고 디렉토리가 아닌 일반 파일인 경우에만 로드
        if (file.endsWith(".md")) {
          const filePath = path.join(harnessDir, file);
          const stat = fs.statSync(filePath);
          if (stat.isFile()) {
            const content = fs.readFileSync(filePath, "utf-8");
            appendedPrompt += `\n\n--- FILE: .harness/harness/${file} ---\n\n${content}`;
          }
        }
      }
    } catch (err) {
      ctx.ui.notify(`Failed to read harness guidelines: ${err}`, "error");
    }

    if (appendedPrompt) {
      return {
        systemPrompt:
          event.systemPrompt +
          "\n\n## SYSTEM GUIDELINES & PERSONAS (Dynamically loaded from .harness/harness/)" +
          appendedPrompt
      };
    }
  });
}
