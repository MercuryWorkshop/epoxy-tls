import {
	init,
	version,
	EpoxyClient,
	JsProtocolExtension,
	JsProtocolExtensionBuilder,
	TorSocketProvider,
	WebSocketJsProvider,
	WispSocketProvider,
} from "./dist/extended.bundled.js";

console.log(version);

await init();

class PasswordExt extends JsProtocolExtension {
	toSend;
	required;

	constructor(required, toSend) {
		super(0x02, [], []);
		this.toSend = toSend;
		this.required = required;
	}

	encode() {
		if (this.toSend) {
			let [_user, _pw] = this.toSend;
			let user = new TextEncoder().encode(_user);
			let pw = new TextEncoder().encode(_pw);

			let arr = new Uint8Array(3 + user.byteLength + pw.byteLength);
			arr[0] = user.byteLength;
			new DataView(arr.buffer).setUint16(1, pw.byteLength, true);
			arr.set(user, 3);
			arr.set(pw, 3 + user.byteLength);

			return arr;
		}
		return new Uint8Array();
	}
}

class PasswordExtBuilder extends JsProtocolExtensionBuilder {
	toSend;

	constructor(toSend) {
		super(0x02);

		this.toSend = toSend;
	}

	buildFromBytes(bytes) {
		console.log("password required:", bytes[0]);
		return new PasswordExt(bytes[0] !== 0);
	}

	buildToExtension() {
		return new PasswordExt(undefined, this.toSend);
	}
}

let wisptoken = localStorage["wisptoken"];

const provider = new WispSocketProvider(
	new WebSocketJsProvider(),
	/*
	"wss://puter.cafe/",
	() => [{ builders: [new PasswordExtBuilder(["", wisptoken])] }, [0x02]]
	*/
	"wss://anura.pro/"
);

await provider.replaceMux();

/*
let exts = await provider.getExtensions();
console.log(exts.get(0));
exts.drop();
*/

const client = new EpoxyClient(provider);

let ret = await client.fetch("https://httpbin.org/post", {
	method: "POST",
	body: JSON.stringify({ a: "b" }),
	headers: {
		"Content-Type": "application/json",
		"x-AbC": "abc",
		"X-BbC": "bcd",
	},
});
console.log(ret);
console.log(ret.rawHeaders);
console.log(await ret.text());

console.log(await client.fetch("https://example.com").then((r) => r.text()));

function withTimeout(promise, label, ms = 15000) {
	return Promise.race([
		promise,
		new Promise((_, reject) =>
			setTimeout(
				() => reject(new Error(`${label} timed out after ${ms}ms`)),
				ms
			)
		),
	]);
}

function assertBytesEqual(actual, expected, message) {
	assert(actual instanceof Uint8Array, `${message}: expected Uint8Array`);
	assert(
		actual.byteLength === expected.byteLength,
		`${message}: expected ${expected.byteLength} bytes, got ${actual.byteLength}`
	);
	for (let i = 0; i < expected.byteLength; i++) {
		assert(actual[i] === expected[i], `${message}: mismatch at index ${i}`);
	}
}

async function testWebSocket() {
	let websocketEchoCandidates = ["wss://ws.ifelse.io"];

	let ws;
	let lastErr;
	for (let endpoint of websocketEchoCandidates) {
		try {
			ws = await withTimeout(
				client.websocket(endpoint),
				`websocket connect ${endpoint}`
			);
			console.log("websocket connected", endpoint);
			break;
		} catch (error) {
			lastErr = error;
			console.warn("websocket connect failed", endpoint, error);
		}
	}

	if (!ws) {
		throw new Error(
			`failed to connect to any websocket echo endpoint: ${lastErr}`
		);
	}

	assert(
		ws.headers instanceof Headers,
		"websocket headers is not a Headers object"
	);
	assert(
		ws.headers.get("upgrade")?.toLowerCase() === "websocket",
		`expected websocket upgrade header, got ${ws.headers.get("upgrade")}`
	);
	assert(
		typeof ws.rawHeaders === "object" && ws.rawHeaders !== null,
		"websocket rawHeaders missing"
	);

	let textPayload = `epoxy websocket test ${Date.now()}`;
	let binaryPayload = new Uint8Array([0, 1, 2, 3, 4, 5, 254, 255]);

	let writer = ws.writable.getWriter();
	let reader = ws.readable.getReader();

	await withTimeout(writer.write(textPayload), "websocket text write");
	await withTimeout(writer.write(binaryPayload), "websocket binary write");

	let gotTextEcho = false;
	let gotBinaryEcho = false;
	let seenMessages = [];
	let start = Date.now();
	while ((!gotTextEcho || !gotBinaryEcho) && Date.now() - start < 12000) {
		let { done, value } = await withTimeout(
			reader.read(),
			"websocket echo read",
			4000
		);
		if (done) {
			throw new Error("websocket stream closed before receiving echo payloads");
		}

		if (typeof value === "string") {
			seenMessages.push(value);
			if (value === textPayload) {
				gotTextEcho = true;
			}
		} else if (value instanceof Uint8Array) {
			seenMessages.push(`binary:${value.byteLength}`);
			if (value.byteLength === binaryPayload.byteLength) {
				assertBytesEqual(
					value,
					binaryPayload,
					"websocket binary echo mismatch"
				);
				gotBinaryEcho = true;
			}
		}
	}

	assert(
		gotTextEcho,
		`websocket text echo not received (seen: ${JSON.stringify(seenMessages)})`
	);
	assert(
		gotBinaryEcho,
		`websocket binary echo not received (seen: ${JSON.stringify(seenMessages)})`
	);
	console.log("websocket echo ok", {
		text: gotTextEcho,
		binary: gotBinaryEcho,
	});

	reader.releaseLock();
	writer.releaseLock();

	ws.close({ closeCode: 1000, reason: "demo done" });
	let closeInfo = await withTimeout(ws.closed, "websocket close", 5000);
	console.log("websocket close", closeInfo);
}

await testWebSocket();

async function sendTest(read, write, log, data) {
	let j = (x) => JSON.stringify(x);
	console.log(`sending ${j(data)} over ${log}`);
	await write.getWriter().write(new TextEncoder().encode(data));
	console.log(`sent ${j(data)} over ${log}`);
	let decoder = new TextDecoder();
	let received = "";
	let got = false;
	let reader = read.getReader();
	try {
		while (true) {
			let { done, value: chunk } = await reader.read();
			if (done) break;

			let decoded = decoder.decode(chunk, { stream: true });
			received += decoded;
			console.log(`decoded ${j(decoded)} over ${log}`);
			if (received.includes(data)) {
				got = true;
				break;
			}
		}
	} finally {
		reader.releaseLock();
	}
	if (!got)
		throw new Error(
			`failed to get ${j(data)} over ${log} (received ${j(received)})`
		);
}

let tcp = await client.connect("tcpbin.com", 4242);
await sendTest(tcp.read, tcp.write, "tcp", ":3\n");

let tls = await client.connectTls("tcpbin.com", 4243);
await sendTest(tls.read, tls.write, "tls", ":3\n");

function assert(condition, message) {
	if (!condition) {
		throw new Error(message);
	}
}

async function testRedirects() {
	let target = "https://httpbin.org/get?redirected=1";
	let redirectUrl = `https://httpbin.org/redirect-to?url=${encodeURIComponent(target)}`;

	let followed = await client.fetch(redirectUrl, { redirect: "follow" });
	let followedBody = await followed.text();
	assert(
		followed.status === 200,
		`expected follow status 200, got ${followed.status}`
	);
	assert(
		followed.url === target,
		`expected follow url ${target}, got ${followed.url}`
	);
	console.log("redirect follow", {
		status: followed.status,
		url: followed.url,
		body: followedBody,
	});

	let manual = await client.fetch(redirectUrl, { redirect: "manual" });
	let manualBody = await manual.text();
	assert(
		manual.status === 302,
		`expected manual status 302, got ${manual.status}`
	);
	assert(
		manual.headers.get("location") === target,
		`expected manual location ${target}, got ${manual.headers.get("location")}`
	);
	console.log("redirect manual", {
		status: manual.status,
		url: manual.url,
		location: manual.headers.get("location"),
		body: manualBody,
	});

	try {
		await client.fetch(redirectUrl, { redirect: "error" });
		console.error("redirect error unexpectedly succeeded");
	} catch (error) {
		console.log("redirect error", error);
	}

	let cappedErrored = false;
	try {
		await client.fetch("https://httpbin.org/absolute-redirect/21", {
			redirect: "follow",
		});
	} catch (error) {
		cappedErrored = true;
		assert(
			String(error).includes("Too many redirects"),
			`expected capped redirect error to include 'Too many redirects', got ${error}`
		);
		console.log("redirect capped", error);
	}
	assert(cappedErrored, "expected capped redirect to throw");
}

try {
	await testRedirects();
} catch (e) {
	console.warn("redirects test failed (non-fatal, moving on):", e);
}

async function testTor() {
	let backend =
		new URL(globalThis.location?.href ?? "http://localhost/").searchParams.get(
			"tor"
		) ?? "wisp";

	console.log(`tor: setting up provider (backend=${backend})`);
	let torBackend =
		backend === "snowflake"
			? { snowflake: { log: (msg) => console.debug(`[snowflake] ${msg}`) } }
			: provider;
	let torProvider = new TorSocketProvider(torBackend, {
		load: (key) => localStorage.getItem(`tor:${key}`),
		store: (key, value) => localStorage.setItem(`tor:${key}`, value),
	});
	torProvider.onProgress((p) => {
		console.log(
			`tor: progress ${(p.frac * 100).toFixed(1)}% ready=${p.ready} ${p.description}` +
				(p.blocked ? ` BLOCKED: ${p.blocked.kind} (${p.blocked.message})` : "")
		);
	});

	console.log("tor: bootstrapping (this can take 30-60s)");
	let bootstrapStart = Date.now();
	await withTimeout(torProvider.bootstrap(), "tor bootstrap", 120000);
	console.log(`tor: bootstrapped in ${Date.now() - bootstrapStart}ms`);

	let torClient = new EpoxyClient(torProvider);

	console.log("tor: fetching tcpbin.com via raw TCP through Tor");
	let tcp = await withTimeout(
		torClient.connect("tcpbin.com", 4242),
		"tor tcp connect",
		60000
	);
	await withTimeout(
		sendTest(tcp.read, tcp.write, "tor-tcp", "hello-tor\n"),
		"tor tcp echo",
		60000
	);

	console.log("tor: fetching check.torproject.org");
	let resp = await withTimeout(
		torClient.fetch("https://check.torproject.org/"),
		"tor fetch",
		60000
	);
	let body = await resp.text();
	let usingTor = body.includes("Congratulations") && body.includes("Tor");
	assert(
		usingTor,
		`check.torproject.org didn't confirm tor usage (status=${resp.status})`
	);
	console.log("tor: check.torproject.org confirmed tor exit");

	console.log("tor: fetching DuckDuckGo .onion");
	let onionResp = await withTimeout(
		torClient.fetch(
			"https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"
		),
		"tor onion fetch",
		90000
	);
	let onionBody = await onionResp.text();
	assert(
		onionResp.status === 200 && onionBody.toLowerCase().includes("duckduckgo"),
		`onion fetch unexpected (status=${onionResp.status} body length=${onionBody.length})`
	);
	console.log(
		`tor: .onion fetch ok (status=${onionResp.status}, ${onionBody.length} bytes)`
	);
}

await testTor();

console.log("done");
