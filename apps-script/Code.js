/**
 * 고객사 지도 웹앱 - Google Sheets 저장 엔드포인트
 *
 * 인증 방식(2026-08 개편): 종전의 공유 토큰(SECRET_TOKEN) 한 개로 통과시키던 구조를 폐기하고,
 * 클라이언트(index.html)가 구글 로그인으로 받은 ID 토큰을 함께 보내면 이 서버가 그 토큰을
 * 검증한 뒤 승인된 계정만 통과시킨다. 승인 계정 목록은 코드가 아니라 스크립트 속성에 있다. 배포 자체는 "모든 사용자"로 열려 있고
 * 실제 접근 통제는 전적으로 이 파일의 verifyIdToken_ 이 담당한다.
 *
 * 통신은 POST 하나로 통일했다. 브라우저에서 다른 도메인(map.b2bc-coway.com)으로부터 호출되는데,
 * Content-Type 을 text/plain 으로 보내면 CORS 사전 요청(preflight OPTIONS)이 발생하지 않아
 * 그대로 통과하고 응답 본문까지 읽을 수 있다(application/json 으로 보내면 preflight 때문에
 * 실패한다 - 실측 확인). 그래서 요청 본문은 text/plain 으로 실려 온 JSON 문자열이며
 * e.postData.contents 에서 꺼내 쓴다. 종전의 JSONP(callback)·숨김 iframe 폼 전송은 모두 폐기했다.
 */

// 승인된 계정 목록이 담긴 스크립트 속성의 키. 목록 자체는 코드에 두지 않는다 -
// 이 저장소는 public 이라, 목록을 코드에 박으면 "이 계정만 뚫으면 고객 데이터에 닿는다"를
// 공개하는 것이 된다(인증이 구글 로그인 + 화이트리스트 한 겹이기 때문). 규칙("화이트리스트로
// 거른다")은 코드에 남기고 값("누구인가")만 밖으로 뺀 것이다.
//
// 넣는 곳: Apps Script 편집기 > 프로젝트 설정(Project Settings) > 스크립트 속성(Script Properties).
// 담는 형식: 쉼표로 구분한다(공백·줄바꿈도 구분자로 함께 인정한다). 예) a@x.com, b@y.com
var ALLOWED_EMAILS_PROPERTY = 'ALLOWED_EMAILS';

// 이 웹앱이 신뢰하는 OAuth 클라이언트 ID 목록. 비밀값이 아니며 웹 클라이언트 ID는 index.html 에도 그대로 들어간다.
// aud 검증의 기준값이라 반드시 실제 값과 일치해야 한다(목록에 없는 aud 의 토큰은 모두 거부된다).
// 클라이언트를 목록에 넣는 것은 "그 앱에서 받은 토큰을 받아 준다"는 뜻일 뿐이며,
// 계정 통제는 여전히 아래 승인 계정 목록이 맡는다.
var OAUTH_CLIENT_IDS = [
  '110059101361-123fl3hr468polbh9thlud980jrv1vbo.apps.googleusercontent.com', // 웹 - 고객사 관리 웹앱(index.html)
  '110059101361-ibalm546ffmli4glblnad87n4fsaqeen.apps.googleusercontent.com'  // 데스크톱 - 고객사 관리 문자 발송 자동화
];

var TOKENINFO_URL = 'https://oauth2.googleapis.com/tokeninfo?id_token=';
var VALID_ISSUERS = ['accounts.google.com', 'https://accounts.google.com'];

function doGet(e) {
  // 조회도 POST 로만 받는다. 종전 GET+JSONP 경로는 토큰 폐기와 함께 없앴다.
  return json_({ ok: false, error: 'method-not-allowed' });
}

function doPost(e) {
  // 어떤 예외도 밖으로 새지 않게 전체를 감싼다. 예외가 그대로 터지면 Apps Script 가
  // CORS 헤더 없는 HTML 오류 페이지를 반환하는데, 그러면 브라우저에서는 응답을 읽지 못해
  // 원인 불명의 네트워크 오류로만 보인다(실제로 이 때문에 한 번 헤맸다).
  try {
    var body = parseBody_(e);
    if (!body) return json_({ ok: false, error: 'invalid-body' });

    var auth = verifyIdToken_(body.idToken);
    if (!auth.ok) {
      // reason 은 클라이언트가 재로그인 여부를 판단하는 용도이며 데이터는 일절 싣지 않는다.
      return json_({ ok: false, error: 'unauthorized', reason: auth.reason });
    }

    switch (body.action) {
      // 로그인 화면이 "이 계정이 승인된 계정인가"만 확인하는 용도. 데이터를 싣지 않으므로
      // 승인되지 않은 계정은 고객사 데이터를 한 건도 받지 못한 채 관문에서 걸러진다.
      // 시트를 열지 않는 것도 의도된 것이다 - 인증 관문이 데이터 저장소 상태에 묶이면
      // 시트 이름 변경·권한 문제만으로 로그인 자체가 막힌다.
      case 'ping':      return json_({ ok: true, email: auth.email });
      case 'load':      return json_(handleLoad_(getSheet_()));
      case 'appendLog': return json_(handleAppendLogData_(getSheet_(), body));
      case 'save':      return json_(handleFullSave_(getSheet_(), body));
      default:          return json_({ ok: false, error: 'unknown-action' });
    }
  } catch (err) {
    // 상세 내용은 실행 로그에만 남긴다(소유자만 볼 수 있다). 클라이언트에는 예외 이름만
    // 돌려준다 - Apps Script 예외 메시지에는 스프레드시트 ID 같은 내부 식별자가 섞여 나올 수
    // 있고, 이 응답은 인증에 실패한 요청에도 나가기 때문이다.
    try { console.error('doPost failed: ' + (err && err.stack ? err.stack : err)); } catch (e2) {}
    return json_({ ok: false, error: 'server-error', kind: safeErrName_(err) });
  }
}

// 데이터를 만지는 액션에서만 시트를 연다. 없으면 만든다.
function getSheet_() {
  var ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) throw new Error('no-bound-spreadsheet');
  return ss.getSheetByName('데이터') || ss.insertSheet('데이터');
}

// ── 데이터 저장 형식 (2026-10 칸 나누기) ──────────────────────────────────────
// 구글 시트는 한 칸에 50,000자까지만 들어간다. 종전에는 전체 JSON 을 A1 한 칸에 넣어,
// 데이터가 커지자 저장이 통째로 실패했다(2026-10-05 엑셀 가져오기 142줄 유실의 원인).
// 그래서 JSON 문자열을 A열 여러 칸에 나눠 쓰고, 읽을 때 이어 붙인다. load 가 돌려주는
// 데이터 모양은 그대로라 화면 코드와 문자발송은 바뀌지 않는다.
//
// 칸마다 "~번호/전체칸수:조각" 형식으로 쓴다.
//  - 머리의 "~" 덕분에 조각이 = + - @ 나 숫자로 시작해도 시트가 수식·숫자로 바꾸지 않는다.
//  - 전체 칸 수를 칸마다 적어 두므로, 데이터가 줄어 뒤쪽에 옛 칸이 남아도 읽을 때 섞이지 않고,
//    번호·칸 수가 하나라도 어긋나면 읽기를 거부한다(깨진 데이터를 정상인 척 돌려주지 않는다).
//  - 모든 칸을 setValues 한 번으로 쓴다(남는 뒤쪽 칸은 같은 호출에서 빈 값으로 지운다).
// A1 이 "~" 로 시작하지 않으면 예전 형식(A1 한 칸에 JSON 통째)으로 읽는다 - 첫 저장 전까지의 호환.
// 주의: 한 번 이 형식으로 저장된 뒤 예전 코드로 되돌리면 예전 코드는 A1 만 읽어 corrupt-data 가 된다.
var CHUNK_SIZE_ = 40000;
var CHUNK_HEAD_RE_ = /^~(\d+)\/(\d+):/;

function readBlob_(sheet) {
  var first = sheet.getRange(1, 1).getValue();
  first = (first === null || first === undefined) ? '' : String(first);
  if (first.charAt(0) !== '~') return first; // 예전 형식
  var m = CHUNK_HEAD_RE_.exec(first);
  if (!m || m[1] !== '1') throw new Error('chunk-header');
  var total = parseInt(m[2], 10);
  if (!(total >= 1)) throw new Error('chunk-header');
  var vals = sheet.getRange(1, 1, total, 1).getValues();
  var parts = [];
  for (var i = 0; i < total; i++) {
    var cell = String(vals[i][0]);
    var mm = CHUNK_HEAD_RE_.exec(cell);
    if (!mm || parseInt(mm[1], 10) !== i + 1 || parseInt(mm[2], 10) !== total) throw new Error('chunk-mismatch');
    parts.push(cell.substring(mm[0].length));
  }
  return parts.join('');
}

function splitChunks_(text) {
  var chunks = [];
  var pos = 0;
  while (pos < text.length) {
    var end = Math.min(pos + CHUNK_SIZE_, text.length);
    // 이모지 같은 글자(UTF-16 두 단위)가 칸 경계에서 반으로 갈리지 않게 한 단위 당긴다.
    if (end < text.length) {
      var code = text.charCodeAt(end - 1);
      if (code >= 0xD800 && code <= 0xDBFF) end -= 1;
    }
    chunks.push(text.substring(pos, end));
    pos = end;
  }
  if (chunks.length === 0) chunks.push('');
  return chunks;
}

function writeBlob_(sheet, text) {
  var chunks = splitChunks_(String(text));
  var n = chunks.length;
  var rows = Math.max(n, sheet.getLastRow());
  var out = [];
  for (var i = 0; i < rows; i++) {
    out.push([i < n ? ('~' + (i + 1) + '/' + n + ':' + chunks[i]) : '']);
  }
  sheet.getRange(1, 1, rows, 1).setValues(out);
}

// 클라이언트에 내보내도 안전한 예외 이름만 통과시킨다. 목록에 없는 이름은 전부 'Error' 로
// 뭉개서, 예외 이름·메시지를 통해 내부 정보가 흘러나갈 여지를 없앤다.
function safeErrName_(err) {
  var KNOWN = ['TypeError', 'ReferenceError', 'RangeError', 'SyntaxError', 'Error'];
  try {
    var name = (err && err.name) ? String(err.name) : 'Error';
    return KNOWN.indexOf(name) === -1 ? 'Error' : name;
  } catch (e2) {
    return 'Error';
  }
}

/**
 * 승인 계정 목록을 스크립트 속성에서 읽어 소문자 배열로 돌려준다.
 * 목록을 확보하지 못하면 빈 배열이 아니라 null 을 돌려준다 - 이것이 핵심이다.
 *
 * 빈 배열은 "아무도 통과 못한다"로도, "제한이 없다"로도 읽힐 수 있다. 뒤쪽으로 읽는 코드가
 * 한 줄이라도 생기면 인증이 통째로 열린다. null 은 그렇게 오독할 수 없어서, 호출부가
 * "목록 없음 = 거부"를 빠뜨리기 어렵다. 속성이 없을 때 getProperty 가 null 을 주는 것도
 * 그대로 이 규약에 실린다(공식 문서: "or null if no such key exists").
 */
function allowedEmails_() {
  var raw;
  try {
    raw = PropertiesService.getScriptProperties().getProperty(ALLOWED_EMAILS_PROPERTY);
  } catch (err) {
    // 속성 저장소를 못 읽는 상황(권한·일시 장애)에서도 통과시키지 않는다.
    return null;
  }
  if (!raw) return null;

  var list = String(raw).split(/[\s,]+/)
    .map(function (s) { return s.trim().toLowerCase(); })
    .filter(function (s) { return s.length > 0; });

  return list.length ? list : null;
}

/**
 * 구글 ID 토큰을 검증한다. 공식 문서가 요구하는 항목(서명·aud·iss·exp)을 모두 확인하며,
 * 서명 검증은 tokeninfo 엔드포인트에 위임한다(Apps Script 에는 구글 공식 검증 라이브러리를
 * 쓸 수 없다). tokeninfo 는 서명이 유효할 때만 200 + 페이로드를 돌려주므로,
 * "200 이 아니면 무조건 거부"로 처리하면 실패 시 상태 코드가 무엇이든 안전하게 막힌다.
 *
 * aud 확인이 이 함수의 핵심이다 - 다른 서비스용으로 발급된 구글 ID 토큰도 서명은 정상이라,
 * aud 를 확인하지 않으면 남의 앱에서 받은 토큰으로 이 엔드포인트를 통과할 수 있다.
 */
function verifyIdToken_(idToken) {
  if (!idToken || typeof idToken !== 'string') return { ok: false, reason: 'missing-token' };

  // 승인 계정 목록을 가장 먼저 확보한다. 목록이 없으면 토큰이 아무리 정상이어도 통과시키지
  // 않는다(fail-closed). 아래 두 갈래(캐시 적중 / tokeninfo 신규 검증)가 모두 이 목록을
  // 쓰므로, 여기서 한 번 막으면 두 갈래가 함께 막힌다.
  var allowed = allowedEmails_();
  if (!allowed) return { ok: false, reason: 'allowlist-unavailable' };

  // 같은 토큰의 재검증을 짧게 캐시한다(저장 1회에 조회+저장 2요청이 연달아 나가기 때문).
  // 캐시 수명은 토큰 자체의 남은 수명을 넘지 않게 잘라서, 만료된 토큰이 통과하지 않게 한다.
  var cache = CacheService.getScriptCache();
  var cacheKey = 'idt_' + Utilities.base64Encode(
    Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, idToken, Utilities.Charset.UTF_8)
  );
  var cachedEmail = cache.get(cacheKey);
  if (cachedEmail) {
    // 화이트리스트에서 뺀 계정이 캐시가 살아 있는 동안 계속 통과하지 않도록 다시 확인한다.
    if (allowed.indexOf(cachedEmail) === -1) return { ok: false, reason: 'not-allowed' };
    return { ok: true, email: cachedEmail };
  }

  var res;
  try {
    res = UrlFetchApp.fetch(TOKENINFO_URL + encodeURIComponent(idToken), { muteHttpExceptions: true });
  } catch (err) {
    return { ok: false, reason: 'tokeninfo-unreachable' };
  }
  if (res.getResponseCode() !== 200) return { ok: false, reason: 'bad-token' };

  var info;
  try {
    info = JSON.parse(res.getContentText());
  } catch (err) {
    return { ok: false, reason: 'tokeninfo-parse-failed' };
  }

  if (OAUTH_CLIENT_IDS.indexOf(String(info.aud)) === -1) return { ok: false, reason: 'aud-mismatch' };
  if (VALID_ISSUERS.indexOf(String(info.iss)) === -1) return { ok: false, reason: 'iss-mismatch' };

  var exp = parseInt(info.exp, 10);
  var now = Math.floor(Date.now() / 1000);
  if (!exp || exp <= now) return { ok: false, reason: 'expired' };

  // 구글이 소유를 보증하지 않는 주소로는 통과시키지 않는다.
  if (String(info.email_verified) !== 'true') return { ok: false, reason: 'email-unverified' };

  var email = String(info.email || '').toLowerCase();
  if (allowed.indexOf(email) === -1) return { ok: false, reason: 'not-allowed' };

  var ttl = Math.min(300, exp - now - 10);
  if (ttl > 0) cache.put(cacheKey, email, ttl);

  return { ok: true, email: email };
}

function parseBody_(e) {
  try {
    if (e && e.postData && e.postData.contents) return JSON.parse(e.postData.contents);
  } catch (err) {
    // 아래에서 null 로 처리한다.
  }
  return null;
}

function json_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

function handleLoad_(sheet) {
  // 잠금 없이 읽는다. 조회가 저장 잠금을 기다리다 시간 초과로 실패하면, 이 엔드포인트를 읽는
  // 문자발송 프로그램이 모르는 오류 종류(lock-timeout)가 새로 생기기 때문이다. 대신 여러 칸을 쓰는
  // 도중에 읽어 칸이 어긋나거나 JSON 해석이 안 되면 0.5초 뒤 한 번 다시 읽는다. 그래도 안 되면
  // 종전과 같은 corrupt-data 로 답한다 - 응답 모양과 오류 종류는 v6.02 와 같다.
  for (var attempt = 0; attempt < 2; attempt++) {
    try {
      var raw = readBlob_(sheet);
      var data = raw ? JSON.parse(raw) : { customers: [], categories: [], routeHistory: [] };
      return { ok: true, data: data };
    } catch (err) {
      if (attempt === 0) Utilities.sleep(500);
    }
  }
  return { ok: false, error: 'corrupt-data' };
}

// 고객사ID(+주소ID)를 찾아 logs[]에 이력 1건만 append하고 결과 객체를 반환한다(순수 데이터,
// ContentService 래핑은 json_가 담당). LockService로 동시 실행을 반드시 직렬화해서
// "읽고-수정하고-쓰기" 중간에 다른 요청이 끼어들어 서로의 변경을 덮어쓰는 것을 막는다.
function handleAppendLogData_(sheet, params) {
  var customerId = params.customerId;
  var addressId = params.addressId || null;
  var logType = params.logType;
  var logDate = params.logDate;
  var logMemo = params.logMemo || '';

  if (!customerId || !logDate || ['visit', 'call', 'sms'].indexOf(logType) === -1) {
    return { ok: false, error: 'invalid-params' };
  }

  var lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) {
    return { ok: false, error: 'lock-timeout' };
  }
  try {
    var raw;
    try {
      raw = readBlob_(sheet);
    } catch (err) {
      return { ok: false, error: 'corrupt-data' };
    }
    var data;
    try {
      data = raw ? JSON.parse(raw) : { customers: [], categories: [], routeHistory: [] };
    } catch (err) {
      return { ok: false, error: 'corrupt-data' };
    }

    var customer = (data.customers || []).find(function(c) { return c.id === customerId; });
    if (!customer) {
      return { ok: false, error: 'customer-not-found' };
    }

    if (!customer.logs) customer.logs = [];
    customer.logs.push({ type: logType, date: logDate, memo: logMemo, addressId: addressId || undefined });
    writeBlob_(sheet, JSON.stringify(data));
    return { ok: true };
  } finally {
    lock.releaseLock();
  }
}

// 전체저장. handleAppendLogData_와 같은 잠금(getScriptLock)을 공유해서, 부분 업데이트와
// 전체저장 쓰기가 물리적으로 겹쳐 시트가 깨지는 것을 방지한다(다만 "과거 시점 스냅샷으로
// 통째로 덮어써서 방금 추가된 로그를 잃어버릴 위험"까지 완전히 없애진 못한다 - 원래부터
// 있던 구조적 한계).
function handleFullSave_(sheet, params) {
  if (!params.payload) return { ok: false, error: 'no-payload' };

  try {
    JSON.parse(params.payload); // 유효한 JSON인지 검증 후 저장 (깨진 데이터로 덮어쓰기 방지)
  } catch (err) {
    return { ok: false, error: 'invalid-json: ' + err.message };
  }

  var lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) {
    return { ok: false, error: 'lock-timeout' };
  }
  try {
    writeBlob_(sheet, params.payload);
    return { ok: true };
  } finally {
    lock.releaseLock();
  }
}
