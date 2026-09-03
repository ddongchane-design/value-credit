/* Cloudflare Pages — 사이트 전체 비밀번호 게이트 (Basic Auth).
 *
 * functions/ 디렉터리 대신 _worker.js(고급 모드)를 쓴 이유: functions/ 라우팅은 Wrangler로
 * 빌드해야 하지만, _worker.js는 대시보드 드래그&드롭 업로드만으로 그대로 동작한다.
 *
 * 비밀번호는 코드에 두지 않는다. Cloudflare 대시보드에서 환경변수로 넣는다:
 *   SITE_PASSWORD  (필수)  — 접속 비밀번호. 넣을 때 반드시 Encrypt 를 누른다
 *   SITE_USER      (선택)  — 아이디. 안 넣으면 'welrix'
 *
 * 환경변수는 저장만으로는 반영되지 않는다 — 저장한 뒤 한 번 더 배포해야 적용된다.
 */

const REALM = 'Basic realm="chaegwon", charset="UTF-8"';

const askForPassword = () =>
  new Response('인증이 필요합니다.', {
    status: 401,
    headers: { 'WWW-Authenticate': REALM, 'Content-Type': 'text/plain; charset=utf-8' },
  });

/* 길이가 다르면 바로 false, 같으면 전 바이트를 XOR로 끝까지 훑는다.
   앞자리부터 비교하다 틀린 곳에서 빠져나오면 응답 시간차로 비밀번호를 한 글자씩 좁힐 수 있다. */
function equals(a, b) {
  const enc = new TextEncoder();
  const x = enc.encode(a), y = enc.encode(b);
  if (x.byteLength !== y.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < x.byteLength; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

/* _headers 파일은 _worker.js 고급 모드에서 적용이 보장되지 않으므로 여기서 직접 붙인다. */
const SECURITY_HEADERS = {
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
};

function authorize(request, env) {
  const password = env.SITE_PASSWORD;
  // 환경변수를 안 넣은 채 배포되면 통과시키지 않는다 — 열린 채 방치되는 쪽이 더 위험하다.
  if (!password) {
    return new Response(
      'SITE_PASSWORD 환경변수가 설정되지 않았습니다.\n' +
      'Cloudflare 대시보드 → 프로젝트 → Settings → Variables and Secrets 에서 추가한 뒤 다시 배포하세요.',
      { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
    );
  }
  const username = env.SITE_USER || 'welrix';

  const header = request.headers.get('Authorization') || '';
  const [scheme, encoded] = header.split(' ');
  if (scheme !== 'Basic' || !encoded) return askForPassword();

  let decoded;
  try {
    // atob는 바이트를 문자로 돌려주므로, 한글 비밀번호를 위해 UTF-8로 다시 디코딩한다.
    const raw = atob(encoded);
    decoded = new TextDecoder().decode(Uint8Array.from(raw, c => c.charCodeAt(0)));
  } catch {
    return askForPassword();
  }

  const sep = decoded.indexOf(':');
  if (sep < 0) return askForPassword();

  // 아이디가 틀려도 비밀번호 비교를 건너뛰지 않는다 — 분기로 시간차가 생기지 않게.
  const okUser = equals(decoded.slice(0, sep), username);
  const okPass = equals(decoded.slice(sep + 1), password);
  if (!okUser || !okPass) return askForPassword();

  return null;   // 통과
}

export default {
  async fetch(request, env) {
    const denied = authorize(request, env);
    if (denied) return denied;

    const response = await env.ASSETS.fetch(request);
    // ASSETS가 돌려준 응답은 불변이라 헤더를 붙이려면 새로 감싼다.
    const out = new Response(response.body, response);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
    return out;
  },
};
