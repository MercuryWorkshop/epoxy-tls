// Snowflake broker rendezvous client.
//
// POSTs to <broker>/client with body
//   "1.0\n" + JSON({offer, nat, fingerprint})
// where `offer` is itself a JSON-encoded {type, sdp} blob (matching
// `util.SerializeSessionDescription` in the snowflake repo). The broker
// responds with `{answer}` where `answer` is similarly a JSON-encoded
// {type, sdp} blob.

export interface BrokerExchangeArgs {
	brokerUrl: string;
	offerSdp: string;
	fingerprint: string;
	nat?: "unknown" | "restricted" | "unrestricted";
}

export async function brokerExchange({
	brokerUrl,
	offerSdp,
	fingerprint,
	nat = "unknown",
}: BrokerExchangeArgs): Promise<string> {
	const offerEnvelope = JSON.stringify({ type: "offer", sdp: offerSdp });
	const body = new TextEncoder().encode(
		"1.0\n" +
			JSON.stringify({
				offer: offerEnvelope,
				nat,
				fingerprint,
			})
	);

	const resolved = new URL("client", brokerUrl).toString();
	// `text/plain` is on fetch's CORS-safelisted-content-type list, so this
	// stays a "simple request" and doesn't trigger a preflight OPTIONS that
	// the broker would refuse. The broker doesn't read the header.
	const res = await fetch(resolved, {
		method: "POST",
		body,
		headers: {
			"Content-Type": "text/plain",
		},
	});

	if (!res.ok) {
		throw new Error(`snowflake broker returned HTTP ${res.status}`);
	}

	const json = (await res.json()) as { answer?: string; error?: string };
	if (json.error) {
		throw new Error(`snowflake broker: ${json.error}`);
	}
	if (!json.answer) {
		throw new Error("snowflake broker: empty response");
	}
	const inner = JSON.parse(json.answer) as { type?: string; sdp?: string };
	if (!inner.sdp) {
		throw new Error("snowflake broker: answer envelope missing sdp");
	}
	return inner.sdp;
}
