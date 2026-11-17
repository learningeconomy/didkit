use did_ethr::DIDEthr;
use did_method_key::DIDKey;
#[cfg(feature = "did-onion")]
use did_onion::DIDOnion;
use did_pkh::DIDPKH;
// use did_sol::DIDSol;
#[cfg(feature = "did-ion")]
use did_ion::DIDION;
use did_jwk::DIDJWK;
use did_tz::DIDTz;
use did_web::DIDWeb;
#[cfg(feature = "did-webkey")]
use did_webkey::DIDWebKey;
use ssi::did::DIDMethods;
#[cfg(any(feature = "did-onion", feature = "did-ion"))]
use std::env::VarError;

#[cfg(feature = "did-onion")]
lazy_static! {
    static ref DIDONION: DIDOnion = {
        let mut onion = DIDOnion::default();
        if let Some(url) = match std::env::var("DID_ONION_PROXY_URL") {
            Ok(url) => Some(url),
            Err(VarError::NotPresent) => None,
            Err(VarError::NotUnicode(err)) => {
                eprintln!("Unable to parse DID_ONION_PROXY_URL: {:?}", err);
                None
            }
        } {
            onion.proxy_url = url;
        }
        onion
    };
}

#[cfg(feature = "did-ion")]
lazy_static! {
    static ref ION: DIDION = DIDION::new(match std::env::var("DID_ION_API_URL") {
        Ok(string) => Some(string),
        Err(VarError::NotPresent) => None,
        Err(VarError::NotUnicode(err)) => {
            eprintln!("Unable to parse DID_ION_API_URL: {:?}", err);
            None
        }
    });
}

lazy_static! {
    static ref DIDTZ: DIDTz = DIDTz::default();
    pub static ref DID_METHODS: DIDMethods<'static> = {
        let mut methods = DIDMethods::default();
        methods.insert(Box::new(DIDKey));
        methods.insert(Box::new(DIDTZ.clone()));
        methods.insert(Box::new(DIDEthr));
        // methods.insert(&DIDSol);
        methods.insert(Box::new(DIDWeb));
        #[cfg(feature = "did-webkey")]
        methods.insert(Box::new(DIDWebKey));
        methods.insert(Box::new(DIDPKH));
        #[cfg(feature = "did-onion")]
        methods.insert(Box::new(DIDONION.clone()));
        #[cfg(feature = "did-ion")]
        methods.insert(Box::new(ION.clone()));
        methods.insert(Box::new(DIDJWK));
        methods
    };
}
