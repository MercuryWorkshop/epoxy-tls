import epoxy from "./pkg/epoxy-module-bundled.js";

onmessage = async (msg) => {
    console.debug("recieved demo:", msg);
    let [
        should_feature_test,
        should_multiparallel_test,
        should_parallel_test,
        should_multiperf_test,
        should_perf_test,
        should_ws_test,
        should_tls_test,
        should_udp_test,
        should_reconnect_test,
        should_perf2_test,
    ] = msg.data;
    console.log(
        "%cWASM is significantly slower with DevTools open!",
        "color:red;font-size:3rem;font-weight:bold"
    );

    const log = (str) => {
        console.log(str);
        postMessage(str);
    }

    const plog = (str) => {
        console.log(str);
        postMessage(JSON.stringify(str, null, 4));
    }

    const { EpoxyClient, certs } = await epoxy();

    console.log("certs:", certs());

    const tconn0 = performance.now();
    // args: websocket url, user agent, redirect limit 
    let epoxy_client = await new EpoxyClient("ws://localhost:4000", navigator.userAgent, 10);
    const tconn1 = performance.now();
    log(`conn establish took ${tconn1 - tconn0} ms or ${(tconn1 - tconn0) / 1000} s`);

    // epoxy classes are inspectable
    console.log(epoxy_client);
    // you can change the user agent and redirect limit in JS
    epoxy_client.redirectLimit = 15;

    const test_mux = async (url) => {
        const t0 = performance.now();
        await epoxy_client.fetch(url);
        const t1 = performance.now();
        return t1 - t0;
    };

    const test_native = async (url) => {
        const t0 = performance.now();
        await fetch(url, { cache: "no-store" });
        const t1 = performance.now();
        return t1 - t0;
    };

    if (should_feature_test) {
        let formdata = new FormData();
        formdata.append("a", "b");
        for (const url of [
            ["https://httpbin.org/get", {}],
            ["https://httpbin.org/gzip", {}],
            ["https://httpbin.org/brotli", {}],
            ["https://httpbin.org/redirect/11", {}],
            ["https://httpbin.org/redirect/1", { redirect: "manual" }],
            ["https://httpbin.org/post", { method: "POST", body: new URLSearchParams("a=b") }],
            ["https://httpbin.org/post", { method: "POST", body: formdata }],
            ["https://httpbin.org/post", { method: "POST", body: "a" }],
            ["https://httpbin.org/post", { method: "POST", body: (new TextEncoder()).encode("abc") }],
            ["https://httpbin.org/get", { headers: {"a": "b", "b": "c"} }],
            ["https://httpbin.org/get", { headers: new Headers({"a": "b", "b": "c"}) }]
        ]) {
            let resp = await epoxy_client.fetch(url[0], url[1]);
            console.warn(url, resp, Object.fromEntries(resp.headers));
            log(await resp.text());
        }
    } else if (should_multiparallel_test) {
        const num_tests = 10;
        let total_mux_minus_native = 0;
        for (const _ of Array(num_tests).keys()) {
            let total_mux = 0;
            await Promise.all([...Array(num_tests).keys()].map(async i => {
                log(`running mux test ${i}`);
                return await test_mux("https://httpbin.org/get");
            })).then((vals) => { total_mux = vals.reduce((acc, x) => acc + x, 0) });
            total_mux = total_mux / num_tests;

            let total_native = 0;
            await Promise.all([...Array(num_tests).keys()].map(async i => {
                log(`running native test ${i}`);
                return await test_native("https://httpbin.org/get");
            })).then((vals) => { total_native = vals.reduce((acc, x) => acc + x, 0) });
            total_native = total_native / num_tests;

            log(`avg mux (${num_tests}) took ${total_mux} ms or ${total_mux / 1000} s`);
            log(`avg native (${num_tests}) took ${total_native} ms or ${total_native / 1000} s`);
            log(`avg mux - avg native (${num_tests}): ${total_mux - total_native} ms or ${(total_mux - total_native) / 1000} s`);
            total_mux_minus_native += total_mux - total_native;
        }
        total_mux_minus_native = total_mux_minus_native / num_tests;
        log(`total mux - native (${num_tests} tests of ${num_tests} reqs): ${total_mux_minus_native} ms or ${total_mux_minus_native / 1000} s`);
    } else if (should_parallel_test) {
        const num_tests = 10;

        let total_mux = 0;
        await Promise.all([...Array(num_tests).keys()].map(async i => {
            log(`running mux test ${i}`);
            return await test_mux("https://httpbin.org/get");
        })).then((vals) => { total_mux = vals.reduce((acc, x) => acc + x, 0) });
        total_mux = total_mux / num_tests;

        let total_native = 0;
        await Promise.all([...Array(num_tests).keys()].map(async i => {
            log(`running native test ${i}`);
            return await test_native("https://httpbin.org/get");
        })).then((vals) => { total_native = vals.reduce((acc, x) => acc + x, 0) });
        total_native = total_native / num_tests;

        log(`avg mux (${num_tests}) took ${total_mux} ms or ${total_mux / 1000} s`);
        log(`avg native (${num_tests}) took ${total_native} ms or ${total_native / 1000} s`);
        log(`avg mux - avg native (${num_tests}): ${total_mux - total_native} ms or ${(total_mux - total_native) / 1000} s`);
    } else if (should_multiperf_test) {
        const num_tests = 10;
        let total_mux_minus_native = 0;
        for (const _ of Array(num_tests).keys()) {
            let total_mux = 0;
            for (const i of Array(num_tests).keys()) {
                log(`running mux test ${i}`);
                total_mux += await test_mux("https://httpbin.org/get");
            }
            total_mux = total_mux / num_tests;

            let total_native = 0;
            for (const i of Array(num_tests).keys()) {
                log(`running native test ${i}`);
                total_native += await test_native("https://httpbin.org/get");
            }
            total_native = total_native / num_tests;

            log(`avg mux (${num_tests}) took ${total_mux} ms or ${total_mux / 1000} s`);
            log(`avg native (${num_tests}) took ${total_native} ms or ${total_native / 1000} s`);
            log(`avg mux - avg native (${num_tests}): ${total_mux - total_native} ms or ${(total_mux - total_native) / 1000} s`);
            total_mux_minus_native += total_mux - total_native;
        }
        total_mux_minus_native = total_mux_minus_native / num_tests;
        log(`total mux - native (${num_tests} tests of ${num_tests} reqs): ${total_mux_minus_native} ms or ${total_mux_minus_native / 1000} s`);
    } else if (should_perf_test) {
        const num_tests = 10;

        let total_mux = 0;
        for (const i of Array(num_tests).keys()) {
            log(`running mux test ${i}`);
            total_mux += await test_mux("https://httpbin.org/get");
        }
        total_mux = total_mux / num_tests;

        let total_native = 0;
        for (const i of Array(num_tests).keys()) {
            log(`running native test ${i}`);
            total_native += await test_native("https://httpbin.org/get");
        }
        total_native = total_native / num_tests;

        log(`avg mux (${num_tests}) took ${total_mux} ms or ${total_mux / 1000} s`);
        log(`avg native (${num_tests}) took ${total_native} ms or ${total_native / 1000} s`);
        log(`avg mux - avg native (${num_tests}): ${total_mux - total_native} ms or ${(total_mux - total_native) / 1000} s`);
    } else if (should_ws_test) {
        let ws = await epoxy_client.connect_ws(
            () => log("opened"),
            () => log("closed"),
            err => console.error(err),
            msg => log(msg),
            "wss://echo.websocket.events",
            [],
            "localhost"
        );
        while (true) {
            log("sending `data`");
            await ws.send_text("data");
            await (new Promise((res, _) => setTimeout(res, 50)));
        }
    } else if (should_tls_test) {
        let decoder = new TextDecoder();
        let ws = await epoxy_client.connect_tls(
            () => log("opened"),
            () => log("closed"),
            err => console.error(err),
            msg => { console.log(msg); log(decoder.decode(msg)) },
            "google.com:443",
        );
        await ws.send("GET / HTTP 1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n");
        await (new Promise((res, _) => setTimeout(res, 500)));
        await ws.close();
    } else if (should_udp_test) {
        let decoder = new TextDecoder();
        // tokio example: `cargo r --example echo-udp -- 127.0.0.1:5000`
        let ws = await epoxy_client.connect_udp(
            () => log("opened"),
            () => log("closed"),
            err => console.error(err),
            msg => { console.log(msg); log(decoder.decode(msg)) },
            "127.0.0.1:5000",
        );
        while (true) {
            log("sending `data`");
            await ws.send("data");
            await (new Promise((res, _) => setTimeout(res, 50)));
        }
    } else if (should_reconnect_test) {
        while (true) {
            try {
                await epoxy_client.fetch("https://httpbin.org/get");
            } catch(e) {console.error(e)}
            log("sent req");
            await (new Promise((res, _) => setTimeout(res, 500)));
        }
    } else if (should_perf2_test) {
        const num_outer_tests = 10;
        const num_inner_tests = 50;
        let total_mux_multi = 0;
        for (const _ of Array(num_outer_tests).keys()) {
            let total_mux = 0;
            await Promise.all([...Array(num_inner_tests).keys()].map(async i => {
                log(`running mux test ${i}`);
                return await test_mux("https://httpbin.org/get");
            })).then((vals) => { total_mux = vals.reduce((acc, x) => acc + x, 0) });
            total_mux = total_mux / num_inner_tests;

            log(`avg mux (${num_inner_tests}) took ${total_mux} ms or ${total_mux / 1000} s`);
            total_mux_multi += total_mux;
        }
        total_mux_multi = total_mux_multi / num_outer_tests;
        log(`total avg mux (${num_outer_tests} tests of ${num_inner_tests} reqs): ${total_mux_multi} ms or ${total_mux_multi / 1000} s`);

    } else {
        let resp = await epoxy_client.fetch("https://httpbin.org/get");
        console.log(resp, Object.fromEntries(resp.headers));
        plog(await resp.json());
    }
    log("done");
};
