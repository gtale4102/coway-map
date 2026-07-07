const SECRET_TOKEN = '4bd56f919030455fc8d6646a2fa703c1';

function doGet(e) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName('데이터') || ss.insertSheet('데이터');
  const callback = e.parameter.callback;

  if (e.parameter.token !== SECRET_TOKEN) {
    return respond_(callback, { error: 'unauthorized' });
  }

  // 컨택이력 1건 추가(작업 K 2026-07): 전체 재조회/재업로드 없이 서버가 직접 읽고-수정하고-
  // 다시 쓰는 방식이라 응답(성공/실패)을 클라이언트가 바로 읽어야 폴백 여부를 판단할 수 있다.
  // POST+숨김iframe 방식은 크로스오리진이라 응답 본문을 읽을 수 없어서(CORS 제약, 기존 주석
  // 참고), 이미 검증된 GET+JSONP 통로를 그대로 재사용한다(의미상 쓰기 동작이지만 이 앱 내부
  // 통신 방식의 기존 제약 때문에 doGet에서 처리).
  if (e.parameter.action === 'appendLog') {
    return respond_(callback, handleAppendLogData_(sheet, e.parameter));
  }

  const data = sheet.getRange(1,1).getValue();
  const result = data ? JSON.parse(data) : {customers:[], categories:[], routeHistory:[]};
  return respond_(callback, result);
}

function respond_(callback, obj) {
  if (callback) {
    return ContentService.createTextOutput(callback + '(' + JSON.stringify(obj) + ')')
      .setMimeType(ContentService.MimeType.JAVASCRIPT);
  }
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}

// 고객사ID(+주소ID)를 찾아 logs[]에 이력 1건만 append하고 결과 객체를 반환한다(순수 데이터,
// ContentService 래핑은 respond_가 담당). LockService로 동시 실행을 반드시 직렬화해서
// "읽고-수정하고-쓰기" 중간에 다른 요청이 끼어들어 서로의 변경을 덮어쓰는 것을 막는다.
function handleAppendLogData_(sheet, params) {
  const customerId = params.customerId;
  const addressId = params.addressId || null;
  const logType = params.logType;
  const logDate = params.logDate;
  const logMemo = params.logMemo || '';

  if (!customerId || !logDate || ['visit', 'call', 'sms'].indexOf(logType) === -1) {
    return { ok: false, error: 'invalid-params' };
  }

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) {
    return { ok: false, error: 'lock-timeout' };
  }
  try {
    const raw = sheet.getRange(1, 1).getValue();
    let data;
    try {
      data = raw ? JSON.parse(raw) : { customers: [], categories: [], routeHistory: [] };
    } catch (err) {
      return { ok: false, error: 'corrupt-data' };
    }

    const customer = (data.customers || []).find(function(c) { return c.id === customerId; });
    if (!customer) {
      return { ok: false, error: 'customer-not-found' };
    }

    if (!customer.logs) customer.logs = [];
    customer.logs.push({ type: logType, date: logDate, memo: logMemo, addressId: addressId || undefined });
    sheet.getRange(1, 1).setValue(JSON.stringify(data));
    return { ok: true };
  } finally {
    lock.releaseLock();
  }
}

// 폼 POST (application/x-www-form-urlencoded) 처리
// 숨겨진 iframe + form 방식으로 전송되며, URL 길이 제한 없이 대용량 데이터 저장 가능
function doPost(e) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName('데이터') || ss.insertSheet('데이터');

  const params = e.parameter || {};

  if (params.token !== SECRET_TOKEN) {
    return ContentService.createTextOutput('unauthorized').setMimeType(ContentService.MimeType.TEXT);
  }

  if (params.action === 'save' && params.payload) {
    return handleFullSave_(sheet, params);
  }

  return ContentService.createTextOutput('no-op').setMimeType(ContentService.MimeType.TEXT);
}

// 기존 전체저장 로직(그대로) + 잠금만 추가. 응답 형식은 이전과 100% 동일('ok' / 'invalid-json: ...')
// - handleAppendLogData_와 같은 잠금(getScriptLock)을 공유해서, 부분 업데이트와 전체저장 쓰기가
//   물리적으로 겹쳐 시트가 깨지는 것을 방지한다(다만 "과거 시점 스냅샷으로 통째로 덮어써서
//   방금 추가된 로그를 잃어버릴 위험"까지 완전히 없애진 못한다 - 원래부터 있던 구조적 한계).
function handleFullSave_(sheet, params) {
  try {
    JSON.parse(params.payload); // 유효한 JSON인지 검증 후 저장 (깨진 데이터로 덮어쓰기 방지)
  } catch (err) {
    return ContentService.createTextOutput('invalid-json: ' + err.message).setMimeType(ContentService.MimeType.TEXT);
  }

  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) {
    return ContentService.createTextOutput('lock-timeout').setMimeType(ContentService.MimeType.TEXT);
  }
  try {
    sheet.getRange(1,1).setValue(params.payload);
    return ContentService.createTextOutput('ok').setMimeType(ContentService.MimeType.TEXT);
  } finally {
    lock.releaseLock();
  }
}
