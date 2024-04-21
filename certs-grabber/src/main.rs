use std::fmt::Write;

use rustls_pki_types::TrustAnchor;

fn main() {
    let mut code = String::with_capacity(256 * 1_024);
    code.push_str("const ROOTS = [");
    for anchor in webpki_roots::TLS_SERVER_ROOTS {
        let TrustAnchor {
            subject,
            subject_public_key_info,
            name_constraints,
        } = anchor;
        code.write_fmt(format_args!(
            "{{subject:new Uint8Array([{}]),subject_public_key_info:new Uint8Array([{}]),name_constraints:{}}},",
            subject
                .as_ref()
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>().join(","),
            subject_public_key_info
                .as_ref()
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<String>>().join(","),
            if let Some(constraints) = name_constraints {
                format!("new Uint8Array([{}])",constraints
                    .as_ref()
                    .iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>().join(","))
            } else {
                "null".into()
            }
        ))
        .unwrap();
    }
    code.pop();
    code.push_str("];");
    println!("{}", code);
}
