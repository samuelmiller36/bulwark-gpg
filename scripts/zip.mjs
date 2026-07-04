// scripts/zip.mjs
// Portable packager: zips dist/{manifest.json,index.js,media/} into openpgp.zip
// without depending on a system `zip` binary. Uses a minimal store/deflate
// writer built on Node's zlib so it runs anywhere Node does.

import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { deflateRawSync, crc32 } from "node:zlib";
import { join } from "node:path";

const DIST = "dist";
const OUT = "openpgp.zip";

function collect(dir, base = "") {
  const out = [];
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const rel = base ? `${base}/${name}` : name;
    if (statSync(full).isDirectory()) out.push(...collect(full, rel));
    else out.push({ name: rel, data: readFileSync(full) });
  }
  return out;
}

const entries = [];
for (const f of ["manifest.json", "index.js"]) {
  const p = join(DIST, f);
  if (existsSync(p)) entries.push({ name: f, data: readFileSync(p) });
}
if (existsSync(join(DIST, "media"))) entries.push(...collect(join(DIST, "media"), "media"));

// Include the readable source and build config so a reviewer can audit the
// plugin logic and reproduce the bundled dist/index.js (which is an unminified
// esbuild bundle of this source plus openpgp.js@6). These extra files sit
// alongside the entrypoint and are ignored by the host loader.
for (const f of ["package.json", "package-lock.json", "README.md"]) {
  if (existsSync(f)) entries.push({ name: `source/${f}`, data: readFileSync(f) });
}
if (existsSync("src")) entries.push(...collect("src", "source/src"));

const chunks = [];
const central = [];
let offset = 0;

for (const e of entries) {
  const nameBuf = Buffer.from(e.name, "utf8");
  const crc = crc32(e.data) >>> 0;
  const compressed = deflateRawSync(e.data);
  const useStore = compressed.length >= e.data.length;
  const body = useStore ? e.data : compressed;
  const method = useStore ? 0 : 8;

  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(method, 8);
  local.writeUInt16LE(0, 10);
  local.writeUInt16LE(0, 12);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(body.length, 18);
  local.writeUInt32LE(e.data.length, 22);
  local.writeUInt16LE(nameBuf.length, 26);
  local.writeUInt16LE(0, 28);
  chunks.push(local, nameBuf, body);

  const cd = Buffer.alloc(46);
  cd.writeUInt32LE(0x02014b50, 0);
  cd.writeUInt16LE(20, 4);
  cd.writeUInt16LE(20, 6);
  cd.writeUInt16LE(0, 8);
  cd.writeUInt16LE(method, 10);
  cd.writeUInt16LE(0, 12);
  cd.writeUInt16LE(0, 14);
  cd.writeUInt32LE(crc, 16);
  cd.writeUInt32LE(body.length, 20);
  cd.writeUInt32LE(e.data.length, 24);
  cd.writeUInt16LE(nameBuf.length, 28);
  cd.writeUInt16LE(0, 30);
  cd.writeUInt16LE(0, 32);
  cd.writeUInt16LE(0, 34);
  cd.writeUInt16LE(0, 36);
  cd.writeUInt32LE(0, 38);
  cd.writeUInt32LE(offset, 42);
  central.push(Buffer.concat([cd, nameBuf]));

  offset += local.length + nameBuf.length + body.length;
}

const centralBuf = Buffer.concat(central);
const end = Buffer.alloc(22);
end.writeUInt32LE(0x06054b50, 0);
end.writeUInt16LE(entries.length, 8);
end.writeUInt16LE(entries.length, 10);
end.writeUInt32LE(centralBuf.length, 12);
end.writeUInt32LE(offset, 16);

writeFileSync(OUT, Buffer.concat([...chunks, centralBuf, end]));
console.log(`Wrote ${OUT} (${entries.length} entries): ${entries.map((e) => e.name).join(", ")}`);
