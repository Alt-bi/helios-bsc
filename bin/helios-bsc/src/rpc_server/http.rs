//! HTTP transport: the tiny_http listener, its worker pool, and the pre-dispatch rejections (method, Host, Content-Type, body cap).
//!
//! Moved verbatim out of `rpc_server.rs`; see that file's header for why.

use super::*;

pub fn serve(node: Arc<Node>, listen: &str) -> Result<()> {
    let server = Arc::new(Server::http(listen).map_err(|e| anyhow::anyhow!("bind {listen}: {e}"))?);
    eprintln!("helios-bsc RPC on http://{listen}  (wallet mode: latest→Safe)");
    let loopback_only = listen_is_loopback(listen);
    // Keep Safe inside the proof window while idle (~4 Fermi blocks).
    let poller = Arc::clone(&node);
    let _ = std::thread::Builder::new()
        .name("helios-bsc-sync".into())
        .spawn(move || loop {
            std::thread::sleep(Duration::from_millis(1800));
            // Caught for the same reason as a request: an uncaught panic here ends the
            // thread, and nothing restarts it. The chain would then only advance on a
            // request that misses the coalescing window, with no log line saying why.
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poller.poll_sync())) {
                Ok(Err(e)) => eprintln!("background sync: {e}"),
                Err(_) => eprintln!("background sync panicked; poller continues"),
                Ok(Ok(_)) => {}
            }
        });

    let mut workers = Vec::with_capacity(RPC_WORKER_THREADS);
    for i in 0..RPC_WORKER_THREADS {
        let server = Arc::clone(&server);
        let node = Arc::clone(&node);
        workers.push(
            std::thread::Builder::new()
                .name(format!("helios-bsc-rpc-{i}"))
                .spawn(move || {
                    // `recv` hands each request to exactly one worker, so the listener
                    // keeps answering while another worker is blocked in a sync.
                    while let Ok(req) = server.recv() {
                        serve_one(&node, req, loopback_only);
                    }
                })?,
        );
    }
    for w in workers {
        let _ = w.join();
    }
    Ok(())
}

fn serve_one(node: &Node, mut req: tiny_http::Request, loopback_only: bool) {
    let host = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Host"))
        .map(|h| h.value.as_str().to_string());
    if let Some(code) = rpc_http_host_reject(host.as_deref(), loopback_only) {
        let _ = req.respond(Response::from_string("forbidden host").with_status_code(code));
        return;
    }
    // Metrics is the one GET route, and only when explicitly enabled. It sits
    // after the Host check so DNS-rebinding protection still applies, and it is
    // never reachable on the default (metrics-off) build.
    if req.method() == &Method::Get {
        let path = req.url().split('?').next().unwrap_or("");
        if node.metrics_enabled() && path == "/metrics" {
            let body = node.metrics_text();
            let mut resp = Response::from_string(body);
            if let Ok(h) = Header::from_bytes(
                &b"Content-Type"[..],
                &b"text/plain; version=0.0.4; charset=utf-8"[..],
            ) {
                resp.add_header(h);
            }
            let _ = req.respond(resp);
            return;
        }
    }
    if let Some(code) = rpc_http_reject(req.method() == &Method::Post, 0) {
        if code == 405 {
            let _ = req.respond(Response::from_string("POST only").with_status_code(405));
            return;
        }
    }
    let content_type = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Content-Type"))
        .map(|h| h.value.as_str().to_string());
    if let Some(code) = rpc_http_content_type_reject(content_type.as_deref()) {
        let _ = req.respond(Response::from_string("unsupported media type").with_status_code(code));
        return;
    }
    let mut buf = Vec::new();
    let mut limited = req.as_reader().take((MAX_RPC_BODY as u64) + 1);
    limited.read_to_end(&mut buf).ok();
    if let Some(code) = rpc_http_reject(true, buf.len()) {
        let _ = req.respond(Response::from_string("payload too large").with_status_code(code));
        return;
    }
    let out = match node.dispatch_caught(&buf) {
        Ok(v) => v,
        Err(RequestPanicked) => {
            // A panic here used to end the worker: `serve_one` is called from
            // `while let Ok(req) = server.recv()`, so the thread simply left the loop.
            // Four of those and the listener accepted connections nobody answered, while
            // the process stayed up and `/metrics` — which reads only atomics — kept
            // reporting a healthy client. Silent and total.
            //
            // Answering `-32603` keeps the worker in its loop. A panic that poisoned a
            // state lock will then panic again on the next request and be caught again,
            // so the failure is a visible per-request error instead of a dead server, and
            // `helios_bsc_request_panics_total` is there to alert on.
            let mut resp = Response::from_string(
                rpc_err(Value::Null, ERR_INTERNAL, "internal_error").to_string(),
            )
            .with_status_code(500);
            if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
                resp = resp.with_header(h);
            }
            let _ = req.respond(resp);
            return;
        }
    };
    if out.is_null() {
        let _ = req.respond(Response::from_string("").with_status_code(204));
        return;
    }
    let mut resp = Response::from_string(out.to_string());
    if let Ok(h) = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
        resp = resp.with_header(h);
    }
    // Never Access-Control-Allow-Origin: * — a page could then call 127.0.0.1:8545.
    let _ = req.respond(resp);
}

/// `None` = accept. `Some(status)` = HTTP error (405 POST-only / 413 body cap).
pub fn rpc_http_reject(is_post: bool, body_len: usize) -> Option<u16> {
    if !is_post {
        return Some(405);
    }
    if body_len > MAX_RPC_BODY {
        return Some(413);
    }
    None
}

/// Missing Content-Type is ok (curl). JSON media types ok. `text/html` etc. → 415.
pub fn rpc_http_content_type_reject(content_type: Option<&str>) -> Option<u16> {
    let raw = content_type.map(str::trim).filter(|s| !s.is_empty())?;
    let media = raw.split(';').next().unwrap_or(raw).trim();
    let m = media.to_ascii_lowercase();
    if m == "application/json" || m == "application/json-rpc" || m == "application/jsonrequest" {
        None
    } else {
        Some(415)
    }
}
