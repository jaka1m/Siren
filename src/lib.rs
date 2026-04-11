mod common;
mod config;
mod proxy;

use crate::config::Config;
use crate::proxy::*;

use std::collections::HashMap;
use uuid::Uuid;
use worker::*;
use once_cell::sync::Lazy;
use regex::Regex;

static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.+-\d+$").unwrap());
static PROXYKV_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Z]{2})").unwrap());

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    // Membantu debugging jika terjadi panic di Wasm
    console_error_panic_hook::set_once();

    let uuid_str = env.var("UUID").map(|x| x.to_string()).unwrap_or_default();
    let uuid = Uuid::parse_str(&uuid_str).unwrap_or_default();
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_default();
    
    let get_env = |name: &str| env.var(name).map(|x| x.to_string()).unwrap_or_default();

    let config = Config { 
        uuid, 
        proxy_addr: host, 
        proxy_port: 443, 
        main_page_url: get_env("MAIN_PAGE_URL"), 
        sub_page_url: get_env("SUB_PAGE_URL"),
        link_page_url: get_env("LINK_PAGE_URL"),
        converter_page_url: get_env("CONVERTER_PAGE_URL"),
        checker_page_url: get_env("CHECKER_PAGE_URL")
    };

    Router::with_data(config)
        .on_async("/", fe)
        .on_async("/sub", sub)
        .on_async("/link", link)
        .on_async("/converter", converter)
        .on_async("/checker", checker)
        .on_async("/:proxyip", tunnel)
        .on_async("/Geo-Project/:proxyip", tunnel)
        .run(req, env)
        .await
}

// Handler Functions - Diletakkan di luar fungsi main
async fn fe(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.main_page_url.clone()).await
}

async fn sub(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.sub_page_url.clone()).await
}

async fn link(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.link_page_url.clone()).await
}

async fn converter(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.converter_page_url.clone()).await
}

async fn checker(_: Request, cx: RouteContext<Config>) -> Result<Response> {
    get_response_from_url(cx.data.checker_page_url.clone()).await
}

async fn get_response_from_url(url: String) -> Result<Response> {
    if url.is_empty() { return Response::error("Empty URL", 400); }
    let req = Fetch::Url(Url::parse(&url)?);
    let mut res = req.send().await?;
    Response::from_html(res.text().await?)
}

async fn tunnel(req: Request, mut cx: RouteContext<Config>) -> Result<Response> {
    let mut proxyip = cx.param("proxyip").map(|s| s.to_string()).unwrap_or_default();
    
    if PROXYKV_PATTERN.is_match(&proxyip) {
        let kvid_list: Vec<String> = proxyip.split(',').map(|s| s.to_string()).collect();
        let kv = cx.kv("SIREN")?;
        let mut proxy_kv_str = kv.get("proxy_kv").text().await?.unwrap_or_default();
        
        let mut rand_buf = [0u8; 1];
        getrandom::getrandom(&mut rand_buf).map_err(|_| Error::from("Random Fail"))?;

        if proxy_kv_str.is_empty() {
            let req = Fetch::Url(Url::parse("https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json")?);
            let mut res = req.send().await?;
            proxy_kv_str = res.text().await?;
            kv.put("proxy_kv", &proxy_kv_str)?.expiration_ttl(86400).execute().await?;
        }

        let proxy_kv: HashMap<String, Vec<String>> = serde_json::from_str(&proxy_kv_str)?;
        let kv_index = (rand_buf[0] as usize) % kvid_list.len();
        let key = &kvid_list[kv_index];

        if let Some(ips) = proxy_kv.get(key) {
            if !ips.is_empty() {
                let ip_index = (rand_buf[0] as usize) % ips.len();
                proxyip = ips[ip_index].clone().replace(':', "-");
            }
        }
    }

    if PROXYIP_PATTERN.is_match(&proxyip) {
        if let Some((addr, port_str)) = proxyip.split_once('-') {
            if let Ok(port) = port_str.parse() {
                cx.data.proxy_addr = addr.to_string();
                cx.data.proxy_port = port;
            }
        }
    }

    let upgrade = req.headers().get("Upgrade")?.unwrap_or_default();
    if upgrade == "websocket" {
        let WebSocketPair { server, client } = WebSocketPair::new()?;
        server.accept()?;

        // Clone config untuk digunakan di thread Wasm
        let config_data = cx.data.clone();

        wasm_bindgen_futures::spawn_local(async move {
            let events = server.events().expect("Failed to get events");
            if let Err(e) = ProxyStream::new(config_data, &server, events).process().await {
                console_log!("[tunnel error]: {}", e);
            }
        });

        Response::from_websocket(client)
    } else {
        Response::from_html("Siren Wasm - Ready")
    }
}
