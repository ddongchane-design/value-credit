/* 사이트 전체 비밀번호 게이트 (Basic Auth) — Cloudflare Worker + Static Assets.
 *
 * ⚠ 이 파일이 동작하려면 wrangler.jsonc 의 assets.run_worker_first 가 true 여야 한다.
 *   false(기본값)이면 정적 파일 요청이 Worker를 거치지 않고 바로 서빙되어,
 *   이 코드가 실행조차 되지 않은 채 사이트 전체가 공개된다. 실제로 그 사고가 났었다.
 *
 * 비밀번호는 코드에 두지 않는다. 대시보드 Settings → Variables and Secrets:
 *   SITE_PASSWORD  (필수)  — 접속 비밀번호. Type 을 Secret 으로
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

const SECURITY_HEADERS = {
  'X-Robots-Tag': 'noindex, nofollow, noarchive',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
};

function authorize(request, env) {
  const password = env.SITE_PASSWORD;
  // SITE_PASSWORD 가 없으면 잠그지 않고 그냥 연다.
  // 먼저 배포해서 화면을 확인하고, 나중에 잠그고 싶어지면 대시보드에서 SITE_PASSWORD 를
  // 넣고 재배포하기만 하면 된다 — 코드는 손댈 필요 없다.
  if (!password) return null;
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
    // ASSETS가 돌려준 응답은 불변이라 헤더를 고치려면 새로 감싼다.
    const out = new Response(response.body, response);
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);

    // charset이 빠지면 브라우저가 레거시 인코딩으로 떨어져 한글이 깨진다.
    // HTML 쪽에도 <meta charset>을 넣어 뒀지만, 헤더가 우선이라 여기서도 보장한다.
    const ct = out.headers.get('Content-Type') || '';
    if (/^text\/|\/(javascript|json|xml)/i.test(ct) && !/charset=/i.test(ct)) {
      out.headers.set('Content-Type', ct + '; charset=utf-8');
    }
    return out;
  },
};
