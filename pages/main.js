const msgFlow = document.querySelector('#msg-flow');
const userPubkeyDisplay = document.querySelector('#user-pubkey');
const serverUrlInput = document.querySelector('#server-url');
const roomsInput = document.querySelector('#rooms');
const leaveRoomBtn = document.querySelector('#leave-room');
const joinNewRoomInput = document.querySelector('#join-new-room');
const chatInput = document.querySelector('#chat');
const regenKeyBtn = document.querySelector('#regen-key');

let serverUrl = null;
let curRoom = null;
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
    }

    log('keypair generated');
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

async function genAuthHeader() {
    return {
        headers: {
            'Authorization': await signData({ typ: 'auth' }),
        },
    };
}

async function enterRoom(ruuid) {
    log(`loading room: ${ruuid}`);
    curRoom = ruuid;
    roomsInput.value = ruuid;

    genAuthHeader()
    .then(opts => fetch(`${serverUrl}/room/${ruuid}`, opts))
    .then(async (resp) => [resp.status, await resp.json()])
    .then(async ([status, json]) => {
        if (status !== 200) throw new Error(`status ${status}: ${json.error.message}`);
        document.title = `room: ${json.title}`
    })
    .catch((e) => {
        log(`failed to get room metadata: ${e}`);
    });

    genAuthHeader()
    .then(opts => fetch(`${serverUrl}/room/${ruuid}/item`, opts))
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
    serverUrl = newServerUrl;

    if (ws !== null) {
        ws.close();
    }

    log('connecting server');
    wsUrl.protocol = wsUrl.protocol == 'http:' ? 'ws:' : 'wss:';
    wsUrl.pathname += wsUrl.pathname.endsWith('/') ? 'ws' : '/ws';
    ws = new WebSocket(wsUrl);
    ws.onopen = async (_) => {
        const auth = await signData({ typ: 'auth' });
        await ws.send(auth);
        log(`listening events on server: ${serverUrl}`);
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
            if (msg.chat.signee.payload.room === curRoom) {
                await showChatMsg(msg.chat);
            } else {
                console.log('ignore background room item');
            }
        } else if (msg.lagged !== undefined) {
            log('some events are dropped because of queue overflow')
        } else {
            log(`unknown ws message: ${e.data}`);
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
            const resp = await fetch(`${serverUrl}/room?filter=${filter}`, await genAuthHeader())
            const json = await resp.json()
            if (resp.status !== 200) throw new Error(`status ${resp.status}: ${json.error.message}`);
            for (const { ruuid, title, attrs } of json.rooms) {
                const el = document.createElement('option');
                el.value = ruuid;
                el.innerText = `${title} (uuid=${ruuid}, attrs=${attrs})`;
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

async function joinRoom(ruuid) {
    try {
        joinNewRoomInput.disabled = true;
        await signAndPost(`${serverUrl}/room/${ruuid}/admin`, {
            // sorted fields.
            permission: 1, // POST_CHAT
            room: ruuid,
            typ: 'add_member',
            user: await getUserPubkey(),
        });
        log('joined room');
        await loadRoomList(false)
        await enterRoom(ruuid);
    } catch (e) {
        console.error(e);
        log(`failed to join room: ${e}`);
    } finally {
        joinNewRoomInput.disabled = false;
    }
}

async function leaveRoom() {
    try {
        leaveRoomBtn.disabled = true;
        await signAndPost(`${serverUrl}/room/${curRoom}/admin`, {
            room: curRoom,
            typ: 'remove_member',
            user: await getUserPubkey(),
        });
        log('left room');
        await loadRoomList(true);
    } catch (e) {
        console.error(e);
        log(`failed to leave room: ${e}`);
    } finally {
        leaveRoomBtn.disabled = false;
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
    if (keypair === null || curRoom === null || text === '') return;

    chatInput.disabled = true;

    try {
        let richText;
        if (text.startsWith('[')) {
            richText = JSON.parse(text);
        } else {
            richText = [text];
        }
        await signAndPost(`${serverUrl}/room/${curRoom}/item`, {
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
    if (serverUrlInput.value === '' && defaultConfig.server_url) {
        serverUrlInput.value = defaultConfig.server_url;
    }
    if (serverUrlInput.value !== '') {
        await connectServer(serverUrlInput.value);
    }
};
serverUrlInput.onchange = async (e) => {
    await connectServer(e.target.value);
};
chatInput.onkeypress = async (e) => {
    if (e.key === 'Enter') {
        await postChat(chatInput.value);
    }
};
regenKeyBtn.onclick = async (_) => {
    await generateKeypair();
};
leaveRoomBtn.onclick = async (_) => {
    await leaveRoom();
};
roomsInput.onchange = async (_) => {
    await enterRoom(roomsInput.value);
};
joinNewRoomInput.onchange = async (_) => {
    await joinRoom(joinNewRoomInput.value);
};
document.querySelector('#refresh-rooms').onclick = async (_) => {
    await loadRoomList(true);
};
