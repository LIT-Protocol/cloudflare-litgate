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
        .get("/", |req, _| {
            // LIT Developers: Change this to whatever URL you want to redirect to if auth works properly
            let protected_url = "https://cdn.cloudflare.steamstatic.com/steam/apps/256843487/movie480_vp9.webm?t=1626712506";

            // Do not change this.  it is hardcoded to the Lit Network Master Public Key
            let network_pubkey_string = "9971e835a1fe1a4d78e381eebbe0ddc84fde5119169db816900de796d10187f3c53d65c1202ac083d099a517f34a9b62";
            let pubkey_bytes: [u8; 48] = <[u8; 48]>::from_hex(network_pubkey_string).expect("Decoding failed");
            let pubkey = PublicKey::from_bytes(pubkey_bytes).expect("parsing pubkey failed");

            let url_vars: HashMap<_, _> = req.url().expect("url parsing failed").query_pairs().into_owned().collect();
            
            let no_jwt = "no_jwt".to_string();
            let jwt = url_vars.get("jwt").unwrap_or(&no_jwt);
            if  jwt == "no_jwt"{
                return Response::error("JWT parameter not passed in", 400)
            }
            println!("JWT: {:?}", jwt);

            let jwt_parts = jwt.split(".").collect::<Vec<&str>>();
            if jwt_parts.len() != 3 {
                return Response::error("JWT does not have 3 parts", 400)
            }
            let sig_from_jwt_base64 = jwt_parts[2];
            let jwt_header = String::from_utf8(base64::decode_config(jwt_parts[0], base64::URL_SAFE).expect("Failed to parse JSON")).expect("Failed to convert bytes to string for jwt header");
            let jwt_payload = String::from_utf8(base64::decode_config(jwt_parts[1], base64::URL_SAFE).expect("Failed to parse JSON")).expect("Failed to convert bytes to string for jwt payload");
            let mut sig_from_jwt: [u8; 96] = [0; 96];
            let decode_res = base64::decode_config_slice(sig_from_jwt_base64, base64::URL_SAFE, &mut sig_from_jwt);
            if let Err(_) = decode_res {
                return Response::error("Signature could not be decoded from base64", 400)
            } 

            let json_header: serde_json::Value = serde_json::from_str(&jwt_header)?;
            let json_payload: serde_json::Value = serde_json::from_str(&jwt_payload)?;

            println!("JWT header: {:?}", json_header);
            println!("JWT payload: {:?}", json_payload);

            let msg = format!("{:}.{:}", jwt_parts[0], jwt_parts[1]);
            let sig = Signature::from_bytes(sig_from_jwt);
            if let Err(_) = sig {
                return Response::error("Signature is bad and could not be parsed", 400)
            } 
            let verified = pubkey.verify(&sig.unwrap(), msg);

            
            if !verified{
                return Response::error("Signature could not be verified", 401);
            }

            // LIT Developers: change this to the URL you are authenticating
            if json_payload["baseUrl"] != "my-dynamic-content-server.com" {
                return Response::error("JWT baseUrl does not match expected value", 401);
            }

            // LIT Developers: uncomment this and set to the path you are authenticating
            // if (json_payload["path"] != "/expectedPath") {
            //     return Response::error("JWT baseUrl does not match expected value", 401);
            // }

            // LIT Developers: if you expect anything else in orgId, role, or extraData, make sure you set it
            if json_payload["orgId"] != "" || json_payload["role"] != "" || json_payload["extraData"] != "" {
                return Response::error("JWT payload has unexpected value", 401);
            }

            Response::redirect(Url::parse(protected_url)?)
        })
        .run(req, env)
        .await
}
