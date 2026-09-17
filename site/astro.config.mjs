import { defineConfig } from "astro/config";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

async function htmlFiles(directory) {
  const entries = await fs.readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map((entry) => {
      const item = path.join(directory, entry.name);
      return entry.isDirectory() ? htmlFiles(item) : entry.name.endsWith(".html") ? [item] : [];
    }),
  );
  return nested.flat();
}

function textContent(markup) {
  return markup
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&(?:nbsp|#160);/g, " ")
    .replace(/&(?:ldquo|rdquo|quot);/g, '"')
    .replace(/&(?:rsquo|apos|#39);/g, "'")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

function searchIndex() {
  return {
    name: "repyy-search-index",
    hooks: {
      "astro:build:done": async ({ dir }) => {
        const output = new URL(dir);
        const outputPath = fileURLToPath(output);
        const files = await htmlFiles(outputPath);
        const index = [];
        for (const file of files) {
          if (file.includes(`${path.sep}demo${path.sep}sample${path.sep}`)) continue;
          const html = await fs.readFile(file, "utf8");
          if (!html.includes("docs-searchable")) continue;
          const route = `/${path.relative(outputPath, path.dirname(file)).split(path.sep).filter(Boolean).join("/")}/`;
          const pageTitle = textContent(html.match(/<title>([\s\S]*?)<\/title>/i)?.[1] || route);
          const sections = html.matchAll(/<section\b([^>]*\bdocs-searchable\b[^>]*)>([\s\S]*?)<\/section>/gi);
          for (const section of sections) {
            const id = section[1].match(/\bid="([^"]+)"/)?.[1];
            if (!id) continue;
            const title = textContent(section[2].match(/<h[12][^>]*>([\s\S]*?)<\/h[12]>/i)?.[1] || id);
            index.push({ route, pageTitle, id, title, text: textContent(section[2]).slice(0, 1200) });
          }
        }
        index.sort((a, b) => a.route.localeCompare(b.route) || a.id.localeCompare(b.id));
        await fs.writeFile(new URL("search-index.json", output), `${JSON.stringify(index)}\n`);
      },
    },
  };
}

export default defineConfig({
  output: "static",
  trailingSlash: "always",
  build: { format: "directory" },
  integrations: [searchIndex()],
});
