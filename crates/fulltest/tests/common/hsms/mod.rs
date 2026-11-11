pub mod nethsm;
pub mod pykmip;
pub mod softhsm2;
pub mod yubihsm2;

use domain_kmip::dep::kmip_protocol::net::{TlsClientAuth, TlsServerAuth};
pub use nethsm::Nethsm;
pub use pykmip::Pykmip;
pub use softhsm2::Softhsm2;
pub use yubihsm2::Yubihsm2;

use std::{collections::HashMap, ffi::OsStr, net::SocketAddr};

//------------ Hsm -----------------------------------------------------------

pub trait Hsm {
    // Some for PKCS#11 based HSMs.
    fn lib_path(&self) -> Option<&OsStr>;

    fn env_vars(&self) -> &HashMap<&'static str, String>;

    fn username(&self) -> Option<&str>;

    fn password(&self) -> Option<&str>;

    //Setings for KMIP based HSMs
    fn address(&self) -> Option<SocketAddr> {
        None
    }

    fn tls_client_auth(&self) -> Option<TlsClientAuth> {
        None
    }

    fn tls_server_auth(&self) -> TlsServerAuth {
        TlsServerAuth::None
    }

    fn tls_server_name(&self) -> Option<String> {
        None
    }
}

//------------ Hsms ----------------------------------------------------------

pub enum Hsms {
    Nethsm(Nethsm),
    Pykmip(Pykmip),
    Softhsm2(Softhsm2),
    Yubihsm2(Yubihsm2),
}
impl Hsms {}

impl Hsm for Hsms {
    fn lib_path(&self) -> Option<&OsStr> {
        match self {
            Hsms::Nethsm(hsm) => hsm.lib_path(),
            Hsms::Pykmip(hsm) => hsm.lib_path(),
            Hsms::Softhsm2(hsm) => hsm.lib_path(),
            Hsms::Yubihsm2(hsm) => hsm.lib_path(),
        }
    }

    fn env_vars(&self) -> &HashMap<&'static str, String> {
        match self {
            Hsms::Nethsm(hsm) => hsm.env_vars(),
            Hsms::Pykmip(hsm) => hsm.env_vars(),
            Hsms::Softhsm2(hsm) => hsm.env_vars(),
            Hsms::Yubihsm2(hsm) => hsm.env_vars(),
        }
    }

    fn username(&self) -> Option<&str> {
        match self {
            Hsms::Nethsm(hsm) => hsm.username(),
            Hsms::Pykmip(hsm) => hsm.username(),
            Hsms::Softhsm2(hsm) => hsm.username(),
            Hsms::Yubihsm2(hsm) => hsm.username(),
        }
    }

    fn password(&self) -> Option<&str> {
        match self {
            Hsms::Nethsm(hsm) => hsm.password(),
            Hsms::Pykmip(hsm) => hsm.password(),
            Hsms::Softhsm2(hsm) => hsm.password(),
            Hsms::Yubihsm2(hsm) => hsm.password(),
        }
    }

    fn address(&self) -> Option<SocketAddr> {
        match self {
            Hsms::Nethsm(hsm) => hsm.address(),
            Hsms::Pykmip(hsm) => hsm.address(),
            Hsms::Softhsm2(hsm) => hsm.address(),
            Hsms::Yubihsm2(hsm) => hsm.address(),
        }
    }

    fn tls_client_auth(&self) -> Option<TlsClientAuth> {
        match self {
            Hsms::Nethsm(hsm) => hsm.tls_client_auth(),
            Hsms::Pykmip(hsm) => hsm.tls_client_auth(),
            Hsms::Softhsm2(hsm) => hsm.tls_client_auth(),
            Hsms::Yubihsm2(hsm) => hsm.tls_client_auth(),
        }
    }

    fn tls_server_auth(&self) -> TlsServerAuth {
        match self {
            Hsms::Nethsm(hsm) => hsm.tls_server_auth(),
            Hsms::Pykmip(hsm) => hsm.tls_server_auth(),
            Hsms::Softhsm2(hsm) => hsm.tls_server_auth(),
            Hsms::Yubihsm2(hsm) => hsm.tls_server_auth(),
        }
    }

    fn tls_server_name(&self) -> Option<String> {
        match self {
            Hsms::Nethsm(hsm) => hsm.tls_server_name(),
            Hsms::Pykmip(hsm) => hsm.tls_server_name(),
            Hsms::Softhsm2(hsm) => hsm.tls_server_name(),
            Hsms::Yubihsm2(hsm) => hsm.tls_server_name(),
        }
    }
}
