(async () => {
  console.log(
    "%cWASM is significantly slower with DevTools open!",
    "color:red;font-size:2rem;font-weight:bold"
  );
  await wasm_bindgen("./wstcp_client_bg.wasm");
  const tconn0 = performance.now();
  let wstcp = await new wasm_bindgen.WsTcpWorker("wss://localhost:4000", navigator.userAgent);
  const tconn1 = performance.now();
  console.warn(`conn establish took ${tconn1 - tconn0} ms or ${(tconn1 - tconn0) / 1000} s`);
  const t0 = performance.now();
  await wstcp.fetch("https://httpbin.org/post", { method: "POST", body: "test", headers: { "X-Header-One": "one", "x-header-one": "One", "X-Header-Two": "two" } });
  const t1 = performance.now();
  console.warn(`mux 1 took ${t1 - t0} ms or ${(t1 - t0) / 1000} s`);

  const t2 = performance.now();
  await wstcp.fetch("https://httpbin.org/post", { method: "POST", body: "test", headers: { "X-Header-One": "one", "x-header-one": "One", "X-Header-Two": "two" } });
  const t3 = performance.now();
  console.warn(`mux 2 took ${t3 - t2} ms or ${(t3 - t2) / 1000} s`);

  const t4 = performance.now();
  await fetch("https://httpbin.org/post", { method: "POST", body: "test", headers: { "X-Header-One": "one", "x-header-one": "One", "X-Header-Two": "two" } });
  const t5 = performance.now();
  console.warn(`native took ${t5 - t4} ms or ${(t5 - t4) / 1000} s`);

  alert(`conn establish took ${tconn1 - tconn0} ms or ${(tconn1 - tconn0) / 1000} s\nmux 1 took ${t1 - t0} ms or ${(t1 - t0) / 1000} s\nmux 2 took ${t3 - t2} ms or ${(t3 - t2) / 1000} s\nnative took ${t5 - t4} ms or ${(t5 - t4) / 1000} s`)
})();
