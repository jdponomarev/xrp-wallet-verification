// Lists fixtures/pending/*.json and emits one GitHub Actions notice per wallet still awaiting a
// real capture. Informational only: always exits 0.
import { readdirSync, readFileSync } from 'node:fs';

const dir = new URL('../fixtures/pending/', import.meta.url);
const files = readdirSync(dir)
  .filter((f) => f.endsWith('.json'))
  .sort();

let pending = 0;
for (const file of files) {
  const record = JSON.parse(readFileSync(new URL(file, dir), 'utf8'));
  const captured = record.signature !== null || record.blobHex !== null;
  const wallet = file.replace(/\.json$/, '');
  console.log(
    `${wallet.padEnd(16)} ${captured ? 'captured, move to fixtures/vectors.json' : 'pending'}`,
  );
  if (!captured) {
    pending += 1;
    console.log(`::notice title=Pending wallet capture (${wallet})::${record.notes}`);
  }
}
console.log(`${pending} of ${files.length} wallet captures pending. See fixtures/CAPTURE.md.`);
