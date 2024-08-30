const msgFlow = document.querySelector('#msg-flow');
const userPubkeyDisplay = document.querySelector('#user-pubkey');
const roomUrlInput = document.querySelector('#room-url');
const chatInput = document.querySelector('#chat');
const regenKeyBtn = document.querySelector('#regen-key');

let roomUrl = '';
let roomUuid = null;
let feed = null;
let keypair = null;

function bufToHex(buf) {
    return [...new Uint8Array(buf)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

function hexToBuf(hex) {
    return new Uint8Array(hex.match(/[\da-f]{2}/gi).map(m => parseInt(m, 16)))
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

    try {
        const ser = (k) => crypto.subtle.exportKey('jwk', k);
        localStorage.setItem('keypair', JSON.stringify({
            publicKey: await ser(keypair.publicKey),
            privateKey: await ser(keypair.privateKey),
        }));
    } catch (e) {
        console.error(e);
        log('failed to store keypair into localStorage');
    }
}

async function showChatMsg(chat) {
    let verifyRet = null;
    crypto.subtle.exportKey('raw', keypair.publicKey)
    try {
        const signeeBytes = (new TextEncoder()).encode(JSON.stringify(chat.signee));
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
    for (let [text, attrs] of richText) {
        if (attrs === undefined) attrs = {};
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
    if (url === '' || url == roomUrl) return;
    const match = url.match(/^https?:\/\/.*\/([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\/?/);
    if (match === null) {
        log('invalid room url');
        return;
    }

    if (feed !== null) {
        feed.close();
    }
    roomUrl = url;
    roomUuid = match[1];

    log(`fetching room: ${url}`);

    const auth = await signData({ typ: 'auth' });
    fetch(
        `${url}/item`,
        {
            headers: {
                'Authorization': auth,
            },
        },
    )
    .then((resp) => {
        if (!resp.ok) throw new Error(`status ${resp.status} ${resp.statusText}`);
        return resp.json();
    })
    // TODO: This response format is to-be-decided.
    .then(async (json) => {
        const [{ title }, items] = json
        document.title = `room: ${title}`
        items.reverse();
        for (const [_cid, chat] of items) {
            await showChatMsg(chat);
        }
        log('---history---');
    })
    .catch((e) => {
        log(`failed to fetch history: ${e}`);
    });

    // TODO: There is a time window where events would be lost.

    feed = new EventSource(`${url}/event`);
    feed.onopen = (_) => {
        log('listening on events');
    }
    feed.onerror = (e) => {
        console.error(e);
        log('event listener error');
    };
    feed.onmessage = async (e) => {
        console.log('feed event', e.data);
        const chat = JSON.parse(e.data);
        showChatMsg(chat);
    };
}

async function signData(payload) {
    const userKey = bufToHex(await crypto.subtle.exportKey('raw', keypair.publicKey));
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
            richText = [[text]];
        }
        const signedPayload = await signData({
            typ: 'chat',
            rich_text: richText,
            room: roomUuid,
        });
        const resp = await fetch(`${roomUrl}/item`, {
            method: 'POST',
            cache: 'no-cache',
            body: signedPayload,
            headers: {
                'Content-Type': 'application/json',
            },
        });
        if (!resp.ok) throw new Error(`status ${resp.status} ${resp.statusText}`);
        chatInput.value = '';
    } catch (e) {
        console.error(e);
        log(`failed to post chat: ${e}`);
    } finally {
        chatInput.disabled = false;
    }
}

window.onload = async (_) => {
    if (!await loadKeypair()) {
        await generateKeypair();
    }
    if (keypair !== null) {
        userPubkeyDisplay.value = bufToHex(await crypto.subtle.exportKey('raw', keypair.publicKey));
    }
    connectRoom(roomUrlInput.value);
};
roomUrlInput.onchange = (e) => {
    connectRoom(e.target.value);
};
chatInput.onkeypress = (e) => {
    if (e.key === 'Enter') {
        chatInput.disabled = true;
        postChat(chatInput.value);
        chatInput.disabled = false;
    }
};
regenKeyBtn.onclick = (_) => {
    generateKeypair();
};
