(async () => {
    console.log(
        "%cWASM is significantly slower with DevTools open!",
        "color:red;font-size:2rem;font-weight:bold"
    );
    await wasm_bindgen("./wstcp_client_bg.wasm");
    const tconn0 = performance.now();
    // args: websocket url, user agent, redirect limit 
    let wstcp = await new wasm_bindgen.WsTcp("wss://localhost:4000", navigator.userAgent, 10);
    const tconn1 = performance.now();
    console.warn(`conn establish took ${tconn1 - tconn0} ms or ${(tconn1 - tconn0) / 1000} s`);
    const t0 = performance.now();
    let resp = await wstcp.fetch("http://httpbin.org/redirect/11");
    const t1 = performance.now();

    console.warn(resp);
    console.warn(Object.fromEntries(resp.headers));
    console.warn(await resp.text());
    console.warn(`mux 1 took ${t1 - t0} ms or ${(t1 - t0) / 1000} s`);
})();
