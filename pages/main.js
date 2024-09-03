const msgFlow = document.querySelector('#msg-flow');
const userPubkeyDisplay = document.querySelector('#user-pubkey');
const roomUrlInput = document.querySelector('#room-url');
const chatInput = document.querySelector('#chat');
const regenKeyBtn = document.querySelector('#regen-key');
const joinRoomBtn = document.querySelector('#join-room');

let roomUrl = '';
let roomUuid = null;
let ws = null;
let keypair = null;
let defaultConfig = {};

function bufToHex(buf) {
    return [...new Uint8Array(buf)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

function hexToBuf(hex) {
    return new Uint8Array(hex.match(/[\da-f]{2}/gi).map(m => parseInt(m, 16)))
}

async function getUserPubkey() {
    if (keypair === null) throw new Error('no userkey');
    return bufToHex(await crypto.subtle.exportKey('raw', keypair.publicKey));
}

function appendMsg(el) {
    msgFlow.append(el);
    msgFlow.scrollTo({
        top: msgFlow.scrollTopMax,
        behavior: 'instant',
    })
}

function log(msg, isHtml) {
    const el = document.createElement('span', {});
    el.classList.add('log');
    if (isHtml) {
        el.innerHTML = msg;
    } else {
        el.innerText = msg;
    }
    appendMsg(el)
}

async function loadKeypair() {
    try {
        const rawJson = localStorage.getItem('keypair');
        if (rawJson === null) return false;
        const json = JSON.parse(rawJson)
        keypair = {
            publicKey: await crypto.subtle.importKey('jwk', json.publicKey, { name: 'Ed25519' }, true, ['verify']),
            privateKey: await crypto.subtle.importKey('jwk', json.privateKey, { name: 'Ed25519' }, true, ['sign']),
        };
        log('loaded keypair from localStorage');
        return true;
    } catch (e) {
        console.error(e);
        log('failed to load keypair from localStorage');
        return false;
    }
}

async function generateKeypair() {
    log('generating keypair');
    regenKeyBtn.disabled = true;
    chatInput.disabled = true;
    joinRoomBtn.disabled = true;
    try {
        keypair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    } catch (e) {
        console.error('keygen', e);
        chatInput.disabled = true;
        log(
            `failed to generate keypair, posting is disabled. maybe try Firefox or Safari?
            <a target="_blank" href="https://caniuse.com/mdn-api_subtlecrypto_sign_ed25519">
                check caniuse.com
            </a>
            `,
            true
        );
    }

    log('keypair generated');

    regenKeyBtn.disabled = false;
    chatInput.disabled = false;
    joinRoomBtn.disabled = false;

    try {
        const serialize = (k) => crypto.subtle.exportKey('jwk', k);
        localStorage.setItem('keypair', JSON.stringify({
            publicKey: await serialize(keypair.publicKey),
            privateKey: await serialize(keypair.privateKey),
        }));
    } catch (e) {
        console.error(e);
        log('failed to store keypair into localStorage');
    }
}

async function showChatMsg(chat) {
    let verifyRet = null;
    try {
        const sortKeys = (obj) =>
            Object.fromEntries(Object.entries(obj).sort((lhs, rhs) => lhs[0] > rhs[0]));
        const canonicalJson = chat.signee
        // Just for simplicity. Only this struct is unsorted due to serde implementation.
        canonicalJson.payload = sortKeys(canonicalJson.payload)
        const signeeBytes = (new TextEncoder()).encode(JSON.stringify(canonicalJson));
        const rawkey = hexToBuf(chat.signee.user);
        const senderKey = await crypto.subtle.importKey('raw', rawkey, { name: 'Ed25519' }, true, ['verify']);
        const success = await crypto.subtle.verify('Ed25519', senderKey, hexToBuf(chat.sig), signeeBytes);
        verifyRet = success ? '✔️' : '✖️';
    } catch (e) {
        console.error(e);
        verifyRet = `✖️ ${e}`;
    }

    const shortUser = chat.signee.user.replace(/^(.{4}).*(.{4})$/, '$1…$2');
    const time = new Date(chat.signee.timestamp * 1000).toISOString();

    const el = document.createElement('div', {});
    el.classList.add('msg');
    const elHeader = document.createElement('span', {});
    const elContent = document.createElement('span', {});
    elHeader.innerText = `${shortUser} [${time}] [${verifyRet}]:`;
    elContent.innerHTML = richTextToHtml(chat.signee.payload.rich_text);
    el.appendChild(elHeader);
    el.appendChild(elContent);
    appendMsg(el)
}

function richTextToHtml(richText) {
    let ret = ''
    for (let e of richText) {
        const [text, attrs] = typeof e === 'string' ? [e, {}] : e;
        // Incomplete cases.
        const tags = [
            [attrs.b, 'b'],
            [attrs.i, 'i'],
            [attrs.m, 'code'],
            [attrs.s, 'strike'],
            [attrs.u, 'u'],
        ];
        for (const [cond, tag] of tags) {
            if (cond) ret += `<${tag}>`;
        }
        ret += escapeHtml(text);
        tags.reverse();
        for (const [cond, tag] of tags) {
            if (cond) ret += `</${tag}>`;
        }
    }
    return ret;
}

function escapeHtml(text) {
    return text.replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}

async function connectRoom(url) {
    if (url === '' || url == roomUrl || keypair === null) return;
    const match = url.match(/^https?:\/\/.*\/([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\/?/);
    if (match === null) {
        log('invalid room url');
        return;
    }

    roomUrl = url;
    roomUuid = match[1];

    log(`fetching room: ${url}`);

    const genFetchOpts = async () => ({ headers: { 'Authorization': await signData({ typ: 'auth' }) } });
    genFetchOpts()
    .then(opts => fetch(url, opts))
    .then(async (resp) => { return [resp.status, await resp.json()]; })
    .then(async ([status, json]) => {
        if (status !== 200) throw new Error(`status ${status}: ${json.error.message}`);
        document.title = `room: ${json.title}`
    })
    .catch((e) => {
        log(`failed to get room metadata: ${e}`);
    });

    genFetchOpts()
    .then(opts => fetch(`${url}/item`, opts))
    .then(async (resp) => { return [resp.status, await resp.json()]; })
    .then(async ([status, json]) => {
        if (status !== 200) throw new Error(`status ${status}: ${json.error.message}`);
        const { items } = json
        items.reverse();
        for (const chat of items) {
            await showChatMsg(chat);
        }
        log('---history---');
    })
    .catch((e) => {
        log(`failed to fetch history: ${e}`);
    });

    // TODO: There is a time window where events would be lost.

    await connectWs();
}

async function connectWs() {
    if (ws !== null) {
        ws.close();
    }
    const wsUrl = new URL(roomUrl);
    wsUrl.protocol = wsUrl.protocol == 'http:' ? 'ws:' : 'wss:';
    wsUrl.pathname = '/ws';
    ws = new WebSocket(wsUrl);
    ws.onopen = async (_) => {
        const auth = await signData({ typ: 'auth' });
        await ws.send(auth);
        log('listening on events');
    }
    ws.onclose = (e) => {
        console.error(e);
        log(`ws closed (code=${e.code}): ${e.reason}`);
    };
    ws.onerror = (e) => {
        console.error(e);
        log(`ws error: ${e.error}`);
    };
    ws.onmessage = async (e) => {
        console.log('ws event', e.data);
        const msg = JSON.parse(e.data);
        if (msg.chat !== undefined) {
            showChatMsg(msg.chat);
        } else if (msg.lagged !== undefined) {
            log('some events are dropped because of queue overflow')
        } else {
            log(`unknown ws message: ${e.data}`);
        }
    };
}

async function joinRoom() {
    try {
        joinRoomBtn.disabled = true;
        await signAndPost(`${roomUrl}/admin`, {
            // sorted fields.
            permission: 1, // POST_CHAT
            room: roomUuid,
            typ: 'add_member',
            user: await getUserPubkey(),
        });
        log('joined room');
        await connectWs();
    } catch (e) {
        console.error(e);
        log(`failed to join room: ${e}`);
    } finally {
        joinRoomBtn.disabled = false;
    }
}

async function signAndPost(url, data) {
    const signedPayload = await signData(data);
    const resp = await fetch(url, {
        method: 'POST',
        cache: 'no-cache',
        body: signedPayload,
        headers: {
            'Content-Type': 'application/json',
        },
    });
    if (!resp.ok) {
        const errResp = await resp.json();
        throw new Error(`status ${resp.status}: ${errResp.error.message}`);
    }
    return resp;
}

async function signData(payload) {
    const userKey = await getUserPubkey();
    const nonceBuf = new Uint32Array(1);
    crypto.getRandomValues(nonceBuf);
    const timestamp = (Number(new Date()) / 1000) | 0;
    const signee = {
        nonce: nonceBuf[0],
        payload,
        timestamp,
        user: userKey,
    };

    const signeeBytes = (new TextEncoder()).encode(JSON.stringify(signee));
    const sig = await crypto.subtle.sign('Ed25519', keypair.privateKey, signeeBytes);

    return JSON.stringify({ sig: bufToHex(sig), signee });
}

async function postChat(text) {
    text = text.trim();
    if (keypair === null || roomUuid === null || text === '') return;

    chatInput.disabled = true;

    try {
        let richText;
        if (text.startsWith('[')) {
            richText = JSON.parse(text);
        } else {
            richText = [text];
        }
        await signAndPost(`${roomUrl}/item`, {
            // sorted fields.
            rich_text: richText,
            room: roomUuid,
            typ: 'chat',
        });
        chatInput.value = '';
    } catch (e) {
        console.error(e);
        log(`failed to post chat: ${e}`);
    } finally {
        chatInput.disabled = false;
    }
}

window.onload = async (_) => {
    try {
        const resp = await fetch('./default.json');
        if (resp.ok) {
            defaultConfig = await resp.json();
        }
    } catch (e) {}

    if (!await loadKeypair()) {
        await generateKeypair();
    }
    if (keypair !== null) {
        userPubkeyDisplay.value = await getUserPubkey();
    }
    if (roomUrlInput.value === '' && defaultConfig.room_url) {
        roomUrlInput.value = defaultConfig.room_url;
    }
    await connectRoom(roomUrlInput.value);
};
roomUrlInput.onchange = async (e) => {
    await connectRoom(e.target.value);
};
chatInput.onkeypress = async (e) => {
    if (e.key === 'Enter') {
        await postChat(chatInput.value);
    }
};
regenKeyBtn.onclick = async (_) => {
    await generateKeypair();
};
joinRoomBtn.onclick = async (_) => {
    await joinRoom();
};
