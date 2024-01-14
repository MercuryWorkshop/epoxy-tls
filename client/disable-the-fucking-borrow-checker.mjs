import fs from "fs";
import path from "path";
import binaryen from "binaryen";
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);

const __dirname = path.dirname(__filename);
let fp = path.resolve(__dirname, './wat.wat');
const originBuffer = fs.readFileSync(fp).toString();

// const wasm = binaryen.readBinary(originBuffer);
const wast = originBuffer
  .replace(/\(br_if \$label\$1[\s\n]+?\(i32.eq\n[\s\S\n]+?i32.const -1\)[\s\n]+\)[\s\n]+\)/g, '');
// const distBuffer = binaryen.parseText(wast).emitBinary();

fs.writeFileSync(fp, wast);
