const OWNER =
  /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;

const REPO =
  /^[A-Za-z0-9._-]{1,100}$/u;

const SHA =
  /^[a-f0-9]{40}$/iu;

const HOST =
  /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.vercel\.app$/iu;

export function deploymentIdentity(env, config) {
  const owner = env.VERCEL_GIT_REPO_OWNER;
  const repo = env.VERCEL_GIT_REPO_SLUG;
  const commit = env.VERCEL_GIT_COMMIT_SHA;
  const host = env.VERCEL_URL;

  const supportedStep =
    Number.isInteger(config?.step) && config.step >= 1 && config.step <= 12;
  const originalApi = config?.originalApiUrl;
  let originalUrl = null;
  if (config?.step >= 5) {
    try {
      originalUrl = new URL(originalApi);
    } catch {
      throw new Error('5단계 원본 자료 API 주소를 확인하세요.');
    }
  }

  if (
    env.VERCEL_GIT_PROVIDER !== 'github'
    || !OWNER.test(owner || '')
    || !REPO.test(repo || '')
    || repo === '.'
    || repo === '..'
    || repo.toLowerCase().endsWith('.git')
    || !SHA.test(commit || '')
    || !HOST.test(host || '')
    || !supportedStep
    || (config.step >= 3 && (!Array.isArray(config.allowedRoutes)
      || config.allowedRoutes.length === 0
      || config.allowedRoutes.some(route => typeof route !== 'string' || !route.trim())))
    || (config.step >= 5 && (originalUrl.protocol !== 'https:'
      || originalUrl.username || originalUrl.password
      || originalUrl.search || originalUrl.hash))
    || typeof config.judgeIssuer !== 'string'
    || !/^https:\/\/[a-z0-9-]+\.up\.railway\.app\/defense\/judge$/iu
      .test(config.judgeIssuer)
    || typeof config.sampleMarker !== 'string'
    || !/^[A-Z0-9_]{1,80}$/u.test(config.sampleMarker)
  ) {
    throw new Error(
      '배포 식별 정보를 확인할 수 없습니다. Vercel 시스템 환경변수와 단계 설정을 확인하세요.'
    );
  }

  let publicHost = host.toLowerCase();
  // A preview must retain its own deployment URL. Production may use only
  // the system-provided production hostname matched by the configured root URL.
  const productionHost = env.VERCEL_PROJECT_PRODUCTION_URL;
  if (env.VERCEL_ENV === 'production' && productionHost !== undefined) {
    if (typeof productionHost !== 'string' || !HOST.test(productionHost)) {
      throw new Error('프로덕션 대표주소의 Vercel 시스템 정보를 확인하세요.');
    }
    const canonicalHost = productionHost.toLowerCase();
    const canonicalUrl = `https://${canonicalHost}`;
    if (config.publicAppUrl !== canonicalUrl && config.publicAppUrl !== `${canonicalUrl}/`) {
      throw new Error('프로덕션 대표주소가 단계 설정의 공개 주소와 일치하지 않습니다.');
    }
    publicHost = canonicalHost;
  }

  return {
    schema: 'aleph.defense.deployment.v1',
    step: config.step,
    repoUrl:
      `https://github.com/${owner.toLowerCase()}/${repo.toLowerCase()}`,
    commit: commit.toLowerCase(),
    publicAppUrl:
      `https://${publicHost}`,
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
    ...(config.step >= 3 ? { allowedRoutes: config.allowedRoutes } : {}),
    ...(config.step >= 5 ? { originalApiUrl: originalUrl.href } : {})
  };
}
