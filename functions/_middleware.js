/* Cloudflare Pages Functions — 사이트 전체 비밀번호 게이트 (Basic Auth).
 *
 * 이 파일 하나가 public/ 아래 모든 요청 앞에 붙는다. Git 연동 배포에서는 Cloudflare가
 * functions/ 를 빌드해 Worker로 만들어 준다 — 그래서 _worker.js 를 직접 두지 않는다.
 * (_worker.js 를 출력 디렉터리에 두면 컴파일되지 않고 정적 파일로 올라가, 게이트가
 *  동작하지 않으면서 소스만 URL로 노출된다.)
 *
 * 비밀번호는 코드에 두지 않는다. Cloudflare 대시보드에서 환경변수로 넣는다:
 *   SITE_PASSWORD  (필수)  — 접속 비밀번호. 넣을 때 Type 을 Secret 으로
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

/* public/_headers 가 적용되더라도 한 번 더 덮어쓴다 — 게이트를 통과한 응답에는
   무슨 일이 있어도 이 헤더들이 붙어 있어야 한다. */
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

export const onRequest = async ({ request, env, next }) => {
  const denied = authorize(request, env);
  if (denied) return denied;

  const response = await next();
  // next()가 돌려준 응답은 불변이라 헤더를 붙이려면 새로 감싼다.
  const out = new Response(response.body, response);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
  return out;
};
