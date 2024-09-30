const idUrlInput = document.querySelector('#id-url');
const logFlow = document.querySelector('#log-flow');
const msgFlow = document.querySelector('#msg-flow');
const idPubkeyInput = document.querySelector('#id-pubkey');
const actPubkeyDisplay = document.querySelector('#act-pubkey');
const serverUrlInput = document.querySelector('#server-url');
const roomsInput = document.querySelector('#rooms');
const joinNewRoomInput = document.querySelector('#join-new-room');
const chatInput = document.querySelector('#chat');

let apiUrl = null;
let curRoom = null;
let ws = null;
let keypair = null;
let defaultConfig = {};
let lastCid = null;

function bufToHex(buf) {
    return [...new Uint8Array(buf)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

function hexToBuf(hex) {
    return new Uint8Array(hex.match(/[\da-f]{2}/gi).map(m => parseInt(m, 16)))
}

function getIdPubkey() {
    const s = idPubkeyInput.value.trim();
    if (!s.match(/^[a-zA-Z0-9]{64}$/)) {
        throw new Error(`invalid id_key, please re-enter: ${s}`);
    }
    return s;
}

async function getActPubkey() {
    if (keypair === null) throw new Error('no actkey');
    return bufToHex(await crypto.subtle.exportKey('raw', keypair.publicKey));
}

function appendMsg(parent, el) {
    parent.append(el);
    parent.scrollTo({
        top: parent.scrollTopMax,
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
    appendMsg(logFlow, el)
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
    document.querySelectorAll('input, button, select').forEach((el) => el.disabled = true);
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
        return;
    }

    log('keypair generated');
    actPubkeyDisplay.value = await getActPubkey();
    document.querySelectorAll('input, button, select').forEach((el) => el.disabled = false);

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

async function register() {
    function norm(url) {
        return String(url).endsWith('/') ? url : url + '/';
    }

    try {
        const idUrl = idUrlInput.value.trim();
        if (idUrl === '') return;

        const wellKnownUrl = (new URL(idUrl)) + '.well-known/blah/identity.json';
        log(`fetching ${wellKnownUrl}`);
        const idDescResp = await fetch(wellKnownUrl, { redirect: 'error' });
        if (idDescResp.status !== 200) throw new Error(`status ${idDescResp.status}`);
        const idDescJson = await idDescResp.json()
        if (typeof idDescJson.id_key !== 'string' || idDescJson.id_key.length !== 64) {
            throw new Error('invalid id_key from identity description response');
        }
        idPubkeyInput.value = idDescJson.id_key;

        const getResp = await fetch(`${apiUrl}/user/me`, {
            cache: 'no-store'
        })
        const challenge = parseInt(getResp.headers.get('x-blah-nonce'));
        const difficulty = parseInt(getResp.headers.get('x-blah-difficulty'));
        if (challenge === null) throw new Error('cannot get challenge nonce');

        log('solving challenge')
        const postResp = await signAndPost(`${apiUrl}/user/me`, {
            // sorted fields.
            challenge_nonce: challenge,
            id_key: getIdPubkey(),
            id_url: norm(idUrl),
            server_url: norm(apiUrl.replace(/\/_blah\/?$/, '')),
            typ: 'user_register',
        }, difficulty)
        if (!postResp.ok) throw new Error(`status ${getResp.status}: ${(await getResp.json()).error.message}`);
        log('registered')
    } catch (err) {
        log(`failed to register: ${err}`)
    }
}

async function showChatMsg(chat) {
    let verifyRet = null;
    try {
        const sortKeys = (obj) =>
            Object.fromEntries(Object.entries(obj).sort((lhs, rhs) => lhs[0] > rhs[0]));
        let canonicalJson = chat.signee
        // Just for simplicity.
        canonicalJson.payload = sortKeys(canonicalJson.payload);
        canonicalJson = sortKeys(canonicalJson);
        const signeeBytes = (new TextEncoder()).encode(JSON.stringify(canonicalJson));
        const rawkey = hexToBuf(chat.signee.act_key);
        const senderKey = await crypto.subtle.importKey('raw', rawkey, { name: 'Ed25519' }, true, ['verify']);
        const success = await crypto.subtle.verify('Ed25519', senderKey, hexToBuf(chat.sig), signeeBytes);
        verifyRet = success ? '✔️' : '✖️';
    } catch (e) {
        console.error(e);
        verifyRet = `✖️ ${e}`;
    }

    // TODO: The relationship of id_key and act_key is not verified.
    const shortUser = chat.signee.id_key.replace(/^(.{4}).*(.{4})$/, '$1…$2');
    const time = new Date(chat.signee.timestamp * 1000).toISOString();

    const el = document.createElement('div', {});
    el.classList.add('msg');
    const elHeader = document.createElement('span', {});
    const elContent = document.createElement('span', {});
    elHeader.innerText = `${shortUser} [${time}] [${verifyRet}]:`;
    elContent.innerHTML = richTextToHtml(chat.signee.payload.rich_text);
    el.appendChild(elHeader);
    el.appendChild(elContent);
    appendMsg(msgFlow, el)
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

async function genAuthHeader() {
    return {
        headers: {
            'Authorization': await signData({ typ: 'auth' }),
        },
    };
}

async function enterRoom(rid) {
    log(`loading room: ${rid}`);
    curRoom = rid;
    roomsInput.value = rid;

    msgFlow.replaceChildren();

    let roomMetadata;
    try {
        const resp = await fetch(`${apiUrl}/room/${rid}`, await genAuthHeader());
        roomMetadata = await resp.json();
        if (resp.status !== 200) throw new Error(`status ${resp.status}: ${roomMetadata.error.message}`);
        document.title = `Blah: ${roomMetadata.title}`;
    } catch (err) {
        log(`failed to get room metadata: ${err}`);
    }

    try {
        const resp = await fetch(`${apiUrl}/room/${rid}/msg`, await genAuthHeader());
        const json = await resp.json();
        if (resp.status !== 200) throw new Error(`status ${resp.status}: ${json.error.message}`);
        const { msgs } = json
        msgs.reverse();
        for (const msg of msgs) {
            lastCid = msg.cid;
            await showChatMsg(msg);
            if (msg.cid === roomMetadata.last_seen_cid) {
                const el = document.createElement('span');
                el.innerText = '---last seen---';
                appendMsg(msgFlow, el)
            }
        }
    } catch (err) {
        log(`failed to fetch history: ${err}`);
    }
}

async function connectServer(newServerUrl) {
    if (newServerUrl === '' || keypair === null) return;
    let wsUrl
    try {
        wsUrl = new URL(newServerUrl);
    } catch (e) {
        log(`invalid url: ${e}`);
        return;
    }
    apiUrl = wsUrl.toString() + '_blah';

    if (ws !== null) {
        ws.close();
    }

    log('connecting server');
    wsUrl.protocol = wsUrl.protocol == 'http:' ? 'ws:' : 'wss:';
    wsUrl.pathname += '_blah/ws';
    ws = new WebSocket(wsUrl);
    ws.onopen = async (_) => {
        const auth = await signData({ typ: 'auth' });
        await ws.send(auth);
        log(`listening events on server: ${newServerUrl}`);
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
        if (msg.msg !== undefined) {
            if (msg.msg.signee.payload.room === curRoom) {
                await showChatMsg(msg.msg);
            } else {
                console.log('ignore background room msg');
            }
        } else if (msg.lagged !== undefined) {
            log('some events are dropped because of queue overflow')
        } else {
            log(`unknown ws msg: ${e.data}`);
        }
    };

    loadRoomList(true);
}

async function loadRoomList(autoJoin) {
    log('loading room list');

    async function loadInto(targetEl, filter) {
        const emptyEl = document.createElement('option');
        emptyEl.value = '';
        emptyEl.innerText = '-';
        emptyEl.disabled = true;
        targetEl.replaceChildren(emptyEl);
        targetEl.value = '';

        try {
            const resp = await fetch(`${apiUrl}/room?filter=${filter}`, await genAuthHeader())
            const json = await resp.json()
            if (resp.status !== 200) throw new Error(`status ${resp.status}: ${json.error.message}`);
            for (const { rid, title, attrs, last_msg, last_seen_cid } of json.rooms) {
                const el = document.createElement('option');
                el.value = rid;
                el.innerText = `${title} (rid=${rid}, attrs=${attrs})`;
                if (last_msg !== undefined && last_msg.cid !== last_seen_cid) {
                    el.innerText += ' (unread)';
                }
                targetEl.appendChild(el);
            }
        } catch (err) {
            log(`failed to load room list: ${err}`)
        }
    }

    loadInto(roomsInput, 'joined')
    .then(async (_) => {
        if (autoJoin) {
            const el = roomsInput.querySelector('option:nth-child(2)');
            if (el !== null) {
                await enterRoom(el.value);
            }
        }
    });

    loadInto(joinNewRoomInput, 'public')
}

async function joinRoom(rid) {
    try {
        joinNewRoomInput.disabled = true;
        await signAndPost(`${apiUrl}/room/${rid}/admin`, {
            // sorted fields.
            permission: 1, // POST_CHAT
            room: rid,
            typ: 'add_member',
            user: await getIdPubkey(),
        });
        log('joined room');
        await loadRoomList(false)
        await enterRoom(rid);
    } catch (e) {
        console.error(e);
        log(`failed to join room: ${e}`);
    } finally {
        joinNewRoomInput.disabled = false;
    }
}

async function leaveRoom() {
    try {
        await signAndPost(`${apiUrl}/room/${curRoom}/admin`, {
            room: curRoom,
            typ: 'remove_member',
            user: await getIdPubkey(),
        });
        log('left room');
        await loadRoomList(true);
    } catch (e) {
        console.error(e);
        log(`failed to leave room: ${e}`);
    }
}


async function signAndPost(url, data, difficulty) {
    const signedPayload = await signData(data, difficulty);
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

async function signData(payload, difficulty) {
    const userKey = await getActPubkey();
    const nonceBuf = new Uint32Array(1);
    crypto.getRandomValues(nonceBuf);
    const timestamp = (Number(new Date()) / 1000) | 0;
    const signee = {
        // sorted fields.
        act_key: userKey,
        id_key: getIdPubkey(),
        nonce: nonceBuf[0],
        payload,
        timestamp,
    };
    let signeeBytes = (new TextEncoder()).encode(JSON.stringify(signee));

    if (difficulty !== undefined && difficulty !== 0) {
        const zeroBytes = difficulty >> 3;
        const nonzeroByteMax = 1 << (8 - (difficulty & 7));
        console.log(`sign with difficulty ${difficulty}, zbytes=${zeroBytes}, nzmax=${nonzeroByteMax}`);
        let i = 0;
        let h;
        for (;; i++) {
            h = new Uint8Array(await crypto.subtle.digest('SHA-256', signeeBytes));
            let passed = (h[zeroBytes] < nonzeroByteMax);
            for (let j = 0; j < zeroBytes; j++) passed &&= (h[j] === 0);
            if (passed) break;
            signee.nonce = (signee.nonce + 1) & 0x7FFFFFFF;
            signeeBytes = (new TextEncoder()).encode(JSON.stringify(signee));
        }
        console.log(`challenge complete after ${i} iterations, hash: ${bufToHex(h)}`);
    }

    const sig = await crypto.subtle.sign('Ed25519', keypair.privateKey, signeeBytes);

    return JSON.stringify({ sig: bufToHex(sig), signee });
}

async function postChat(text) {
    text = text.trim();
    if (keypair === null || curRoom === null || text === '') return;

    chatInput.disabled = true;

    try {
        let richText;
        if (text.startsWith('[')) {
            richText = JSON.parse(text);
        } else {
            richText = [text];
        }
        await signAndPost(`${apiUrl}/room/${curRoom}/msg`, {
            // sorted fields.
            rich_text: richText,
            room: curRoom,
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

async function markSeen() {
    try {
        const resp = await fetch(`${apiUrl}/room/${curRoom}/msg/${lastCid}/seen`, {
            method: 'POST',
            headers: (await genAuthHeader()).headers,
        })
        if (!resp.ok) throw new Error(`status ${resp.status}: ${(await resp.json()).error.message}`);
        log('seen')
    } catch (err) {
        log(`failed to mark seen: ${err}`)
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
        actPubkeyDisplay.value = await getActPubkey();
    }
    if (idUrlInput.value === '' && defaultConfig.id_url) {
        idUrlInput.value = defaultConfig.id_url;
    }
    if (idPubkeyInput.value === '' && defaultConfig.id_key) {
        idPubkeyInput.value = defaultConfig.id_key;
    }
    if (serverUrlInput.value === '' && defaultConfig.server_url) {
        serverUrlInput.value = defaultConfig.server_url;
    }
    if (serverUrlInput.value !== '') {
        await connectServer(serverUrlInput.value);
    }
};

function onButtonClick(selector, handler) {
    const el = document.querySelector(selector);
    el.onclick = async () => {
        try {
            el.disabled = true;
            await handler();
        } finally {
            el.disabled = false;
        }
    };
}
onButtonClick('#leave-room', leaveRoom);
onButtonClick('#regen-key', generateKeypair);
onButtonClick('#register', register);
onButtonClick('#refresh-rooms', async () => await loadRoomList(true));
onButtonClick('#mark-seen', markSeen);

serverUrlInput.onchange = async (e) => {
    await connectServer(e.target.value);
};
chatInput.onkeypress = async (e) => {
    if (e.key === 'Enter') {
        await postChat(chatInput.value);
        chatInput.focus();
    }
};
roomsInput.onchange = async (_) => {
    await enterRoom(roomsInput.value);
};
joinNewRoomInput.onchange = async (_) => {
    await joinRoom(joinNewRoomInput.value);
};
