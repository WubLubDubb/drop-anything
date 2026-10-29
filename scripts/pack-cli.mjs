// 把命令行客户端打包到 public/cli/，部署后可以直接用 npx 从网站运行，不用 clone 项目。
// 文件名带内容哈希：npx 按网址缓存，网址不变就不会下载新版本。
// npm pack 生成的包内容和时间戳是固定的，代码没变时哈希也不变。

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const outDir = path.join(root, 'public', 'cli');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'drop-cli-'));

try {
  const out = execFileSync('npm', ['pack', path.join(root, 'cli'), '--pack-destination', tmp, '--json'], {
    encoding: 'utf8',
    shell: process.platform === 'win32',
  });
  const packed = path.join(tmp, JSON.parse(out)[0].filename);
  const data = fs.readFileSync(packed);
  const file = `drop-anything-cli-${createHash('sha256').update(data).digest('hex').slice(0, 12)}.tgz`;

  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, file), data);
  fs.writeFileSync(path.join(outDir, 'latest.json'), JSON.stringify({ file }) + '\n');
  console.log('命令行客户端已打包：public/cli/' + file);
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}
