(async () => {
  console.log(
    "%cWASM is significantly slower with DevTools open!",
    "color:red;font-size:2rem;font-weight:bold"
  );

  const should_test = (new URL(window.location.href)).searchParams.has("test");

  await wasm_bindgen("./wstcp_client_bg.wasm");

  const tconn0 = performance.now();
  // args: websocket url, user agent, redirect limit 
  let wstcp = await new wasm_bindgen.WsTcp("wss://localhost:4000", navigator.userAgent, 10);
  const tconn1 = performance.now();
  console.warn(`conn establish took ${tconn1 - tconn0} ms or ${(tconn1 - tconn0) / 1000} s`);

  for (const url of ["https://httpbin.org/get", "https://httpbin.org/gzip", "https://httpbin.org/brotli"]) {
    let resp = await wstcp.fetch(url);
    console.warn(resp);
    console.warn(Object.fromEntries(resp.headers));
    console.warn(await resp.text());
  }

  if (should_test) {
    const test_mux = async (url) => {
      const t0 = performance.now();
      await wstcp.fetch(url);
      const t1 = performance.now();
      return t1 - t0;
    };

    const test_native = async (url) => {
      const t0 = performance.now();
      await fetch(url);
      const t1 = performance.now();
      return t1 - t0;
    };

    const num_tests = 10;

    let total_mux = 0;
    for (const _ of Array(num_tests).keys()) {
      total_mux += await test_mux("https://httpbin.org/gzip");
    }
    total_mux = total_mux / num_tests;

    let total_native = 0;
    for (const _ of Array(num_tests).keys()) {
      total_native += await test_native("https://httpbin.org/gzip");
    }
    total_native = total_native / num_tests;

    console.warn(`avg mux (10) took ${total_mux} ms or ${total_mux / 1000} s`);
    console.warn(`avg native (10) took ${total_native} ms or ${total_native / 1000} s`);
    console.warn(`mux - native: ${total_mux - total_native} ms or ${(total_mux - total_native) / 1000} s`);
    alert("you can open console now");
  }
})();
