#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as wait } from 'node:timers/promises';

const regionMessage = 'not currently available in your location';
const debugStartupHint = '请完全退出 Antigravity，再运行以下命令启用本机调试端口，然后重新运行脚本。\n' +
  'open -a Antigravity --args --remote-debugging-port=0';

async function getJson(url) {
  const response = await fetch(url, {
    redirect: 'error', signal: AbortSignal.timeout(3500),
  }).catch(error => {
    throw new Error('无法连接 Antigravity 本机调试端口。' + debugStartupHint, { cause: error });
  });
  if (!response.ok) throw new Error('Antigravity 本机调试端口响应异常。' + debugStartupHint);
  return response.json();
}

async function connect(url) {
  const socket = new WebSocket(url);
  const connected = Promise.withResolvers();
  const pending = new Map();
  const handlers = new Map();
  let nextId = 0;
  const connectTimer = setTimeout(() => {
    connected.reject(new Error('连接 Antigravity 调试端口超时。'));
    socket.close();
  }, 4000);

  socket.addEventListener('open', () => connected.resolve(), { once: true });
  socket.addEventListener('error', () => {
    connected.reject(new Error('无法连接 Antigravity 调试端口。'));
  }, { once: true });
  socket.addEventListener('close', () => {
    for (const request of pending.values()) request.reject(new Error('Antigravity 调试连接已关闭。'));
  });
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.method) handlers.get(message.method)?.(message.params);
    const request = pending.get(message.id);
    if (!request) return;
    if (message.error) request.reject(new Error('调试调用失败：' + request.method));
    else request.resolve(message.result);
  });

  try {
    await connected.promise;
  } finally {
    clearTimeout(connectTimer);
  }

  return {
    close: () => socket.close(),
    on: (event, handler) => handlers.set(event, handler),
    async call(method, params = {}, timeoutMs = 5000) {
      const id = ++nextId;
      const request = Promise.withResolvers();
      const timeout = setTimeout(() => request.reject(new Error('调试调用超时：' + method)), timeoutMs);
      pending.set(id, { ...request, method });
      try {
        socket.send(JSON.stringify({ id, method, params }));
        return await request.promise;
      } finally {
        clearTimeout(timeout);
        pending.delete(id);
      }
    }
  };
}

async function evaluate(cdp, expression, contextId, timeoutMs = 9000) {
  const result = await cdp.call('Runtime.evaluate', {
    expression,
    contextId,
    awaitPromise: true,
    returnByValue: true,
  }, timeoutMs);
  if (result.exceptionDetails) throw new Error('无法读取 Antigravity 网页状态。');
  return result.result.value;
}

function readAuthInRenderer(regionMessage, refreshModels = false) {
  return (async () => {
    const csrf = globalThis.__APP_CONFIG__?.csrfToken ||
      localStorage.getItem('agy_session_csrf_token');
    if (!csrf) return { ready: false };
    const headers = {
      'Content-Type': 'application/json',
      'Connect-Protocol-Version': '1',
      'x-codeium-csrf-token': csrf,
    };
    async function getStatus(method, body = {}) {
      const response = await fetch('/exa.language_server_pb.LanguageServerService/' + method, {
        method: 'POST', headers, body: JSON.stringify(body), redirect: 'error',
        signal: AbortSignal.timeout(6500),
      });
      if (!response.ok) throw new Error('Local auth RPC failed');
      return response.json();
    }
    const token = await getStatus('HasAuthToken');
    if (!token.hasToken) return { ready: true, hasToken: false };
    const { authResult } = await getStatus('GetAuthStatus');
    const regionBlocked = authResult?.uiMessage?.includes(regionMessage) === true;
    // Refresh the backend model cache before the main UI reads it after login.
    if (refreshModels && regionBlocked) {
      await getStatus('GetAvailableModels', { forceRefresh: true });
    }
    return {
      ready: true,
      hasToken: true,
      valid: authResult?.hasValidAuth === true,
      regionBlocked,
    };
  })();
}

async function getFrontend(cdp, origin) {
  const { frameTree } = await cdp.call('Page.getFrameTree');
  const { executionContextId } = await cdp.call('Page.createIsolatedWorld', {
    frameId: frameTree.frame.id,
    worldName: 'LocalAntigravityFrontendLoader',
  });
  const context = executionContextId;
  const url = JSON.stringify(origin + '/main.js');
  const length = await evaluate(cdp, `(async () => {
    const response = await fetch(${url}, {
      cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(6500)
    });
    if (!response.ok) throw new Error('Could not load the desktop frontend');
    const source = await response.text();
    globalThis.originalAntigravityFrontend = source;
    return source.length;
  })()`, context);
  try {
    if (!Number.isSafeInteger(length) || length < 1 || length > 25_000_000) {
      throw new Error('Antigravity 前端大小与预期不符。');
    }
    // Small CDP messages avoid the frame limit on this Electron debugger.
    const chunks = [];
    const chunkSize = 192 * 1024;
    for (let offset = 0; offset < length; offset += chunkSize) {
      const source = await evaluate(cdp,
        `globalThis.originalAntigravityFrontend.slice(${offset}, ${offset + chunkSize})`, context);
      if (source.length !== Math.min(chunkSize, length - offset)) {
        throw new Error('读取到的前端代码不完整。');
      }
      chunks.push(source);
    }
    return chunks.join('');
  } finally {
    await evaluate(cdp, 'delete globalThis.originalAntigravityFrontend', context).catch(() => {});
  }
}

function patchFrontend(source, appVersion) {
  // Match the control flow by its property names and literals. Bundlers rename
  // local variables between releases even when these checks keep the same shape.
  const changes = [
    {
      name: '会话资格判断',
      pattern: /if\((?<token>[\w$]+)\.hasToken\)\{(?<lookup>[\s\S]{0,650}?)if\((?<auth>[\w$]+)\?\.hasValidAuth\)\{(?<context>let [\w$]+=\{isGcpTos:\k<auth>\.isGcpTos\?\?!1,)/g,
      replacement({ token, lookup, auth, context }) {
        return 'if(' + token + '.hasToken){' + lookup +
          'if(' + auth + '?.hasValidAuth||(' + token + '.hasToken===!0&&' +
          auth + '?.uiMessage?.includes(' + JSON.stringify(regionMessage) +
          '))){' + context;
      },
    },
    {
      name: '登录页跳转',
      pattern: /;(?<overlay>[\w$]+)=(?<screens>[\w$]+)&&(?<onboarded>[\w$]+)&&(?<state>[\w$]+)!==void 0&&[\w$]+\.has\(\k<state>\);var (?<menu>[\w$]+)=(?<getMenu>[\w$]+)\(\),(?<waiting>[\w$]+)=\k<screens>&&\k<state>==="uninitialized";\k<state>=\k<screens>&&\k<onboarded>&&\(\k<state>==="signedOut"\|\|\k<state>==="loginError"\|\|\k<state>==="projectPicker"\|\|\k<state>==="licensePicker"\);/g,
      replacement({ overlay, menu, getMenu, waiting, state }) {
        return ';' + overlay + '=!1;var ' + menu + '=' + getMenu +
          '(),' + waiting + '=!1;' + state + '=!1;';
      },
    },
    {
      name: '引导页跳转',
      pattern: /;[\w$]+\.hasOnboardingScreens&&[\w$]+!==2&&(?<redirect>\([\w$]+\(\),[\w$]+\(\),[\w$]+\(\{to:"\/onboarding")/g,
      replacement({ redirect }) {
        return ';!1&&' + redirect;
      },
    },
  ];
  for (const change of changes) {
    const matches = Array.from(source.matchAll(change.pattern));
    if (matches.length !== 1) {
      throw new Error('脚本不兼容当前 Antigravity ' + appVersion +
        '。无法唯一定位' + change.name + '。');
    }
    const [match] = matches;
    source = source.slice(0, match.index) + change.replacement(match.groups) +
      source.slice(match.index + match[0].length);
  }
  return source;
}

async function openMain(cdp, origin, source) {
  const url = origin + '/main.js';
  const body = Buffer.from(source, 'utf8').toString('base64');
  const served = Promise.withResolvers();
  const timeout = setTimeout(() => served.reject(new Error('主界面加载前端代码超时。')), 20000);
  cdp.on('Fetch.requestPaused', request => {
    const { requestId } = request;
    if (request.request.url !== url || request.resourceType !== 'Script') {
      void cdp.call('Fetch.continueRequest', { requestId }).catch(served.reject);
      return;
    }
    void cdp.call('Fetch.fulfillRequest', {
      requestId, responseCode: 200,
      responseHeaders: [
        { name: 'Content-Type', value: 'application/javascript; charset=utf-8' },
        { name: 'Cache-Control', value: 'no-store' },
      ],
      body,
    }, 16000).then(served.resolve, served.reject);
  });
  try {
    await cdp.call('Page.enable');
    await cdp.call('Fetch.enable', { patterns: [{ urlPattern: url, resourceType: 'Script' }] });
    const navigation = cdp.call('Page.navigate', { url: origin + '/' }).then(result => {
      if (result.errorText) throw new Error('无法打开 Antigravity 主界面。');
    });
    await Promise.all([served.promise, navigation]);
  } finally {
    clearTimeout(timeout);
    await cdp.call('Fetch.disable').catch(() => {});
  }
}

function readPage() {
  const editor = document.querySelector('[aria-label="Message input"]');
  const modelSelector = document.querySelector('[data-testid="model-selector-trigger"]');
  return {
    path: location.pathname,
    loginBanner: document.body?.innerText.includes('To use the agent, please login') === true,
    editorReady: editor?.isContentEditable === true && Boolean(editor.getClientRects().length),
    modelReady: Boolean(modelSelector?.getClientRects().length) && !modelSelector.disabled,
  };
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length && args[0] !== '--check')) {
    throw new Error('用法：node antigravity-skip-region-page.mjs [--check]');
  }
  if (process.platform !== 'darwin' || Number(process.versions.node.split('.')[0]) < 22) {
    throw new Error('需要 macOS 和 Node.js 22 或更新版本。');
  }
  const portFile = join(homedir(), 'Library', 'Application Support', 'Antigravity', 'DevToolsActivePort');
  const portContents = await readFile(portFile, 'utf8').catch(error => {
    if (error.code === 'ENOENT') {
      throw new Error('找不到 Antigravity 的调试端口文件。2.33.0 起默认关闭此端口。' + debugStartupHint);
    }
    throw error;
  });
  const [port] = portContents.split(/\r?\n/);
  if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) {
    throw new Error('找不到有效的 Antigravity 本机调试端口。');
  }

  const local = 'http://127.0.0.1:' + port;
  const [version, targets] = await Promise.all([
    getJson(local + '/json/version'),
    getJson(local + '/json/list'),
  ]);
  const product = /\bAntigravity(?:\/([^\s]+))?(?=\s|$)/.exec(version['User-Agent'] ?? '');
  if (!product) throw new Error('本机调试端口未识别为 Antigravity。');
  const appVersion = product[1] ?? '（版本未知）';
  const checkOnly = args.length === 1;
  const candidates = targets.filter(target => {
    if (target.type !== 'page' || !target.webSocketDebuggerUrl) return false;
    const page = new URL(target.url);
    const debug = new URL(target.webSocketDebuggerUrl);
    return page.protocol === 'https:' && page.hostname === '127.0.0.1' &&
      (checkOnly || page.pathname === '/onboarding') &&
      debug.protocol === 'ws:' && debug.hostname === '127.0.0.1' && debug.port === port &&
      debug.pathname === '/devtools/page/' + target.id;
  });
  if (candidates.length !== 1) {
    throw new Error('请只保留一个 Antigravity 窗口，并让它停在登录页。');
  }
  const [target] = candidates;
  const origin = new URL(target.url).origin;
  const cdp = await connect(target.webSocketDebuggerUrl);
  try {
    const pageExpression = '(' + readPage.toString() + ')()';
    const auth = await evaluate(cdp, '(' + readAuthInRenderer.toString() + ')(' +
      JSON.stringify(regionMessage) + ', ' + !checkOnly + ')', undefined, 22000);
    if (!auth.ready) throw new Error('登录窗口尚未加载完成。');
    if (!auth.hasToken) throw new Error('本机没有登录令牌。请先正常登录 Google 一次。');
    if (!checkOnly && (auth.valid || !auth.regionBlocked)) {
      throw new Error('当前账号状态不符合地区限制条件。');
    }
    const frontend = await getFrontend(cdp, origin).catch(error => {
      throw new Error(`无法读取 Antigravity ${appVersion} 的前端代码。脚本可能不兼容。${error.message}`, { cause: error });
    });
    const patched = patchFrontend(frontend, appVersion);
    if (checkOnly) {
      console.log(`Antigravity ${appVersion} 的调试端口、令牌状态和前端代码匹配检查通过。` +
        (auth.regionBlocked ? ' 当前账号资格检查显示地区限制。' : ' 当前未检测到地区限制。'));
      return;
    }
    console.log(`正在打开 Antigravity ${appVersion} 主界面…`);
    try {
      await openMain(cdp, origin, patched);
    } catch (error) {
      throw new Error(`脚本可能与当前 Antigravity ${appVersion} 不兼容。${error.message}`, { cause: error });
    }
    for (let attempt = 0; attempt < 26; attempt++) {
      const state = await evaluate(cdp, pageExpression).catch(() => null);
      if (state?.path === '/' && state.editorReady && state.modelReady && !state.loginBanner) {
        console.log('已进入主界面。聊天输入框和模型选择器已就绪。');
        return;
      }
      await wait(750);
    }
    throw new Error(`脚本可能与当前 Antigravity ${appVersion} 不兼容。聊天输入框或模型选择器未就绪。`);
  } finally {
    cdp.close();
  }
}

try {
  await main();
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
