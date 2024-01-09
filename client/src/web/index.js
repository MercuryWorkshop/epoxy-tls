(async () => {
  await wasm_bindgen("./wstcp_client_bg.wasm");
  let wstcp = await new wasm_bindgen.WsTcpWorker("wss://localhost:4000");
  await wstcp.fetch("https://alicesworld.tech");
})();
