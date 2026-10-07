import {
  copyFile,
  mkdir,
  readFile,
  rm,
  writeFile
} from 'node:fs/promises';

import { resolve } from 'node:path';
import { deploymentIdentity } from './deployment-identity.mjs';

const root = resolve(import.meta.dirname, '..');

const source =
  resolve(root, 'data.json');

const output =
  resolve(root, 'public', 'data.json');

const config =
  JSON.parse(
    await readFile(
      resolve(root, 'aleph.config.json'),
      'utf8'
    )
  );

const data =
  JSON.parse(
    await readFile(source, 'utf8')
  );

if (!Array.isArray(data.notes)) {
  throw new Error(
    '가상 자료 형식을 확인하세요. 실제 학생 자료를 넣으면 안 됩니다.'
  );
}

await mkdir(
  resolve(root, 'public'),
  { recursive: true }
);

if (config.step === 1) {
  await copyFile(source, output);

  console.log(
    '실습용 공개 자료를 public/data.json에 복사했습니다.'
  );
} else if (config.step >= 2 && config.step <= 12) {
  if (data.notes.length !== 0) {
    throw new Error(
      '2단계 이후에는 정적 data.json에 메모를 남기면 안 됩니다.'
    );
  }

  if (config.step === 2) {
    await writeFile(
      output,
      `${JSON.stringify({ sampleMarker: config.sampleMarker, notes: [] }, null, 2)}\n`,
      'utf8'
    );
    console.log('2단계 정적 자료 목록을 빈 배열로 유지했습니다.');
  } else {
    await rm(output, { force: true });
    console.log('3단계 이후 공개 data.json을 배포 결과에서 제거했습니다.');
  }
} else {
  throw new Error(
    '지원하지 않는 방어전 단계입니다.'
  );
}

if (!process.argv.includes('--local')) {
  const identity =
    deploymentIdentity(process.env, config);

  await writeFile(
    resolve(root, 'public', 'aleph.json'),
    `${JSON.stringify(identity, null, 2)}\n`,
    'utf8'
  );

  console.log(
    '배포 저장소·커밋·주소를 public/aleph.json에 기록했습니다.'
  );
}
