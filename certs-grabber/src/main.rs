use std::fmt::Write;

use ring::digest::{digest, SHA256};
use rustls_pki_types::{CertificateDer, TrustAnchor};
use webpki::anchor_from_trusted_cert;
use webpki_ccadb::fetch_ccadb_roots;

#[tokio::main]
async fn main() {
    let tls_roots_map = fetch_ccadb_roots().await;
    let mut code = String::with_capacity(256 * 1_024);
    code.push_str("const ROOTS = [");
    for (_, root) in tls_roots_map {
        // Verify the DER FP matches the metadata FP.
        let der = root.der();
        let calculated_fp = digest(&SHA256, &der);
        let metadata_fp = hex::decode(&root.sha256_fingerprint).expect("malformed fingerprint");
        assert_eq!(calculated_fp.as_ref(), metadata_fp.as_slice());

        let ta_der = CertificateDer::from(der.as_ref());
        let TrustAnchor {
            subject,
            subject_public_key_info,
            name_constraints,
        } = anchor_from_trusted_cert(&ta_der).expect("malformed trust anchor der");

        /*
        let (_, parsed_cert) =
            x509_parser::parse_x509_certificate(&der).expect("malformed x509 der");
        let issuer = name_to_string(parsed_cert.issuer());
        let subject_str = name_to_string(parsed_cert.subject());
        let label = root.common_name_or_certificate_name.clone();
        let serial = root.serial().to_string();
        let sha256_fp = root.sha256_fp();
        */

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
    println!("{}",code);
}
