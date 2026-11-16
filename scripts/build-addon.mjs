import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const supplied = process.argv[2];
let origin;
try {
  const url = new URL(supplied);
  if (url.protocol !== 'https:' || url.username || url.password || url.port ||
      url.pathname !== '/' || url.search || url.hash ||
      !/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(url.hostname) ||
      /\.(?:localhost|local|internal|invalid|test|example)$/.test(url.hostname) ||
      /^(?:.*\.)?example\.(?:com|org|net)$/.test(url.hostname)) throw new Error();
  origin = url.origin;
} catch {
  console.error('Usage: npm run build:addon -- https://YOUR-PUBLIC-BACKEND-HOST');
  process.exit(1);
}
const manifest = JSON.parse(await readFile(new URL('addon/appsscript.template.json', root), 'utf8'));
manifest.urlFetchWhitelist = [origin + '/'];
await mkdir(new URL('addon/build/', root), { recursive: true });
await writeFile(new URL('addon/build/appsscript.json', root), JSON.stringify(manifest, null, 2) + '\n');
await writeFile(new URL('addon/build/Deployment.js', root), 'var BACKEND_ORIGIN = ' + JSON.stringify(origin) + ';\n');
for (const file of await readdir(new URL('addon/src/', root))) {
  if (file.endsWith('.js')) {
    await writeFile(new URL('addon/build/' + file, root), await readFile(new URL('addon/src/' + file, root)));
  }
}
console.log('Built add-on in ' + fileURLToPath(new URL('addon/build/', root)));
