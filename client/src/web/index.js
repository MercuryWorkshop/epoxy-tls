(async () => {
  console.log(
    "%cWASM is significantly slower with DevTools open!",
    "color:red;font-size:2rem;font-weight:bold"
  );
  await wasm_bindgen("./wstcp_client_bg.wasm");
  const tconn0 = performance.now();
  let wstcp = await new wasm_bindgen.WsTcp("wss://localhost:4000", navigator.userAgent);
  const tconn1 = performance.now();
  console.warn(`conn establish took ${tconn1 - tconn0} ms or ${(tconn1 - tconn0) / 1000} s`);
  const t0 = performance.now();
  let resp = await wstcp.fetch("https://httpbin.org/post", { method: "POST", body: "test", headers: { "X-Header-One": "one", "x-header-one": "One", "X-Header-Two": "two" } });
  const t1 = performance.now();

  console.warn(resp);
  console.warn(await fetch("https://httpbin.org/post", { method: "POST", body: "test", headers: { "X-Header-One": "one", "x-header-one": "One", "X-Header-Two": "two" } }));
  console.warn(Object.fromEntries(resp.headers));
  console.warn(await resp.text());
  console.warn(`mux 1 took ${t1 - t0} ms or ${(t1 - t0) / 1000} s`);
})();
