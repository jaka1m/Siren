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

// Gunakan block inisialisasi yang lebih aman untuk Wasm
static PROXYIP_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^.+-\d+$").unwrap());
static PROXYKV_PATTERN: Lazy<Regex> = Lazy::new(|| Regex::new(r"^([A-Z]{2})").unwrap());

#[event(fetch)]
async fn main(req: Request, env: Env, _: Context) -> Result<Response> {
    // Sangat penting untuk debugging Wasm
    console_error_panic_hook::set_once();

    // Gunakan unwrap_or atau default agar tidak panic jika variabel Env kosong
    let uuid_str = env.var("UUID").map(|x| x.to_string()).unwrap_or_default();
    let uuid = Uuid::parse_str(&uuid_str).unwrap_or_default();
    
    let host = req.url()?.host().map(|x| x.to_string()).unwrap_or_else(|| "127.0.0.1".to_string());
    
    // Gunakan helper untuk ambil env var agar kode lebih bersih dan aman
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

// ... fungsi fe, sub, link, converter, checker tetap sama ...

async fn tunnel(req: Request, mut cx: RouteContext<Config>) -> Result<Response> {
    let mut proxyip = cx.param("proxyip").map(|s| s.to_string()).unwrap_or_default();
    
    if PROXYKV_PATTERN.is_match(&proxyip)  {
        let kvid_list: Vec<String> = proxyip.split(',').map(|s| s.to_string()).collect();
        let kv = cx.kv("SIREN")?;
        
        let mut proxy_kv_str = kv.get("proxy_kv").text().await?.unwrap_or_default();
        
        // Perbaikan getrandom: inisialisasi buffer dengan benar
        let mut rand_buf = [0u8; 1];
        if let Err(_) = getrandom::getrandom(&mut rand_buf) {
            return Err(Error::from("Random generator failed"));
        }

        if proxy_kv_str.is_empty() {
            let req = Fetch::Url(Url::parse("https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json")?);
            let mut res = req.send().await?;
            if res.status_code() == 200 {
                proxy_kv_str = res.text().await?;
                kv.put("proxy_kv", &proxy_kv_str)?.expiration_ttl(86400).execute().await?; 
            } else {
                return Err(Error::from(format!("KV Fetch failed: {}", res.status_code())));
            }
        }

        let proxy_kv: HashMap<String, Vec<String>> = serde_json::from_str(&proxy_kv_str)?;

        let kv_index = (rand_buf[0] as usize) % kvid_list.len();
        let selected_kv_key = &kvid_list[kv_index];

        if let Some(proxies) = proxy_kv.get(selected_kv_key) {
            if !proxies.is_empty() {
                let proxyip_index = (rand_buf[0] as usize) % proxies.len();
                proxyip = proxies[proxyip_index].clone().replace(':', "-");
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

        // Pindahkan data config agar bisa digunakan di thread wasm
        let config_data = cx.data.clone();
        wasm_bindgen_futures::spawn_local(async move {
            let events = server.events().expect("Failed to get events");
            if let Err(e) = ProxyStream::new(config_data, &server, events).process().await {
                console_log!("[tunnel error]: {}", e);
            }
        });

        Response::from_websocket(client)
    } else {
        Response::from_html("Siren Wasm - WebSocket Required")
    }
}

// Helper function (Pastikan Response::from_html menerima String)
async fn get_response_from_url(url: String) -> Result<Response> {
    if url.is_empty() {
        return Response::error("URL is empty", 400);
    }
    let req = Fetch::Url(Url::parse(&url)?);
    let mut res = req.send().await?;
    let body = res.text().await?;
    Response::from_html(body)
}
