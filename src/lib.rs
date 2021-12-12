use serde_json::json;
use worker::*;
extern crate blsttc;
extern crate hex;
use hex::FromHex;
use std::collections::HashMap;
extern crate base64;

use blsttc::{PublicKey, Signature};

mod utils;

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or("unknown region".into())
    );
}

#[event(fetch)]
pub async fn main(req: Request, env: Env) -> Result<Response> {
    log_request(&req);

    // Optionally, get more helpful error messages written to the console in the case of a panic.
    utils::set_panic_hook();

    // Optionally, use the Router to handle matching endpoints, use ":name" placeholders, or "*name"
    // catch-alls to match on specific patterns. Alternatively, use `Router::with_data(D)` to
    // provide arbitrary data that will be accessible in each route via the `ctx.data()` method.
    let router = Router::new();

    // Add as many routes as your Worker needs! Each route will get a `Request` for handling HTTP
    // functionality and a `RouteContext` which you can use to  and get route parameters and
    // Environment bindings like KV Stores, Durable Objects, Secrets, and Variables.
    router
        .get("/", |req, ctx| {
            let network_pubkey_string = "9971e835a1fe1a4d78e381eebbe0ddc84fde5119169db816900de796d10187f3c53d65c1202ac083d099a517f34a9b62";
            let pubkey_bytes: [u8; 48] = <[u8; 48]>::from_hex(network_pubkey_string).expect("Decoding failed");
            let pubkey = PublicKey::from_bytes(pubkey_bytes).expect("parsing pubkey failed");

            let url_vars: HashMap<_, _> = req.url().expect("url parsing failed").query_pairs().into_owned().collect();
            let jwt = url_vars.get("jwt").expect("getting jwt failed");
            let jwt_parts = jwt.split(".").collect::<Vec<&str>>();
            let sig_from_jwt_base64 = jwt_parts[2];
            let mut sig_from_jwt: [u8; 96] = [0; 96];
            base64::decode_config_slice(sig_from_jwt_base64, base64::URL_SAFE, &mut sig_from_jwt);

            let msg = format!("{:}.{:}", jwt_parts[0], jwt_parts[1]);

            // let sig_str = "a8a098bd87503c6d0c8fb1bad7c4c1a9ff4555c3c05b5fdd0c20144cec4a1eddac49079785ddff2120179bf9081a1e49039cefadf9725bed946ec40270e1a82a7a1f64eb1de136873c4b7d93559e8c52282c2bf15de990de3a69c74ef4f6c7f6";
            // let sig_bytes: [u8; 96] = <[u8; 96]>::from_hex(sig_str).expect("Decoding failed");
            let sig = Signature::from_bytes(sig_from_jwt).expect("parsing sig failed");
            // let msg = "eyJhbGciOiJCTFMxMi0zODEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJMSVQiLCJzdWIiOiIweGRiZDM2MGYzMDA5N2ZiNmQ5MzhkY2M4YjdiNjI4NTRiMzYxNjBiNDUiLCJjaGFpbiI6InBvbHlnb24iLCJpYXQiOjE2MzkzMzA5MDMsImV4cCI6MTYzOTM3NDEwMywiYmFzZVVybCI6Im15LWR5bmFtaWMtY29udGVudC1zZXJ2ZXIuY29tIiwicGF0aCI6Ii9jajVuN3FraHdjODZqYmZ1YzltdWd4Iiwib3JnSWQiOiIiLCJyb2xlIjoiIiwiZXh0cmFEYXRhIjoiIn0";

            let verified = pubkey.verify(&sig, msg);
            let resp = format!("Hello from Workers! {:?} and jwt {:?} and sig {:?}", verified, jwt, sig_from_jwt);
            // println!("{:?}",resp);
            Response::ok(resp)
        })
        .post_async("/form/:field", |mut req, ctx| async move {
            if let Some(name) = ctx.param("field") {
                let form = req.form_data().await?;
                match form.get(name) {
                    Some(FormEntry::Field(value)) => {
                        return Response::from_json(&json!({ name: value }))
                    }
                    Some(FormEntry::File(_)) => {
                        return Response::error("`field` param in form shouldn't be a File", 422);
                    }
                    None => return Response::error("Bad Request", 400),
                }
            }

            Response::error("Bad Request", 400)
        })
        .get("/worker-version", |_, ctx| {
            let version = ctx.var("WORKERS_RS_VERSION")?.to_string();
            Response::ok(version)
        })
        .run(req, env)
        .await
}
