// Based on https://github.com/spruceid/r2d2-cryptoki but limited to just the
// RwUser type, as we don't need the other user types, and because we always
// respect CK_TOKEN_INFO ulMaxSessionCount.

use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::thread::available_parallelism;

use cryptoki::context::{Function, Pkcs11};
use cryptoki::error::RvError;
use cryptoki::mechanism::{Mechanism, MechanismInfo, MechanismType};
use cryptoki::session::{Session, SessionState, UserType};
use cryptoki::slot::{Limit, Slot, SlotInfo, TokenInfo};
use cryptoki::types::AuthPin;
use r2d2::ManageConnection;
use tracing::{debug, info, warn};

use crate::client_request_handler::HandleCache;
use crate::pkcs11::error::Error;

pub type Pkcs11Connection = r2d2::PooledConnection<Pkcs11ConnectionManager>;

const DEFAULT_CONCURRENCY: u32 = 8;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HashableMechanismType(MechanismType);

impl HashableMechanismType {
    #[allow(unused)]
    pub fn new(mechanism_type: MechanismType) -> Self {
        Self(mechanism_type)
    }
}

impl std::hash::Hash for HashableMechanismType {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl std::ops::Deref for HashableMechanismType {
    type Target = MechanismType;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<MechanismType> for HashableMechanismType {
    fn from(value: MechanismType) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for HashableMechanismType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone)]
pub struct Pkcs11Pool {
    /// A reference to the PKCS#11 context.
    //
    /// Most accesses to the context should go via the pool.
    pkcs11: Pkcs11,

    /// The PKCS#11 'slot' this pool holds connections for.
    slot: Slot,

    pool: r2d2::Pool<Pkcs11ConnectionManager>,

    token_info: Arc<TokenInfo>,

    slot_info: Arc<SlotInfo>,

    mechanisms: Arc<Mutex<HashMap<HashableMechanismType, MechanismInfo>>>,
}

impl Pkcs11Pool {
    pub fn new(pkcs11: Pkcs11, slot: Slot) -> Result<Self, Error> {
        // Determine and log OS and token properties that limit concurrency.
        // TODO: If the PKCS#11 session has to make a network connection it may
        // be possible to use more PKCS#11 sessions concurrently than O/S CPU
        // cores.
        let max_os_concurrency = max_os_concurrency();
        Self::log_opt_debug_prop(
            "Available parallelism",
            max_os_concurrency.map(|v| v.to_string()),
        );

        // Use the smallest of the found limits, or fallback to a default.
        let max_os_concurrency = max_os_concurrency.unwrap_or(DEFAULT_CONCURRENCY);
        let max_token_concurrency =
            max_token_concurrency(&pkcs11, slot)?.unwrap_or(DEFAULT_CONCURRENCY);
        let min_pool_size = 1;
        let max_pool_size = max_token_concurrency.min(max_os_concurrency);

        debug!("Querying PKCS#11 token and slot properties");
        let token_info = pkcs11.get_token_info(slot)?;
        Self::log_token_info_properties(&token_info);

        let slot_info = pkcs11.get_slot_info(slot)?;
        let wanted_mechanisms = [
            Mechanism::RsaPkcsKeyPairGen,
            Mechanism::EccKeyPairGen,
            Mechanism::EccEdwardsKeyPairGen,
        ];
        let mut found_mechanisms = HashMap::new();

        for mechanism in wanted_mechanisms {
            let mech_type = mechanism.mechanism_type();
            if let Ok(mechanism_info) = pkcs11.get_mechanism_info(slot, mech_type) {
                found_mechanisms.insert(mech_type.into(), mechanism_info);
            }
        }
        Self::log_mechanisms(&found_mechanisms);

        let token_info = Arc::new(token_info);
        let slot_info = Arc::new(slot_info);
        let mechanisms = Arc::new(Mutex::new(found_mechanisms));

        // Create the PKCS#11 connection pool using the established limits.
        info!("Chosen PKCS#11 connection pool limits: min={min_pool_size}, max={max_pool_size}");
        let manager = Pkcs11ConnectionManager::new(
            pkcs11.clone(),
            slot,
            token_info.clone(),
            slot_info.clone(),
            mechanisms.clone(),
        );
        let pool = r2d2::Builder::new()
            .max_size(max_pool_size)
            .min_idle(Some(min_pool_size))
            .test_on_check_out(true)
            .build(manager)
            .map_err(|err| Error::UnusableConfig(err.to_string()))?;

        Ok(Self {
            pkcs11,
            slot,
            pool,
            token_info,
            slot_info,
            mechanisms,
        })
    }

    #[allow(unused)]
    pub fn pkcs11(&self) -> Pkcs11 {
        self.pkcs11.clone()
    }

    #[allow(unused)]
    pub fn slot(&self) -> Slot {
        self.slot
    }

    pub fn user_pin_final_try(&self) -> Result<bool, Error> {
        Ok(self.pkcs11.get_token_info(self.slot)?.user_pin_final_try())
    }

    pub fn token_info(&self) -> &TokenInfo {
        &self.token_info
    }

    pub fn slot_info(&self) -> &SlotInfo {
        &self.slot_info
    }

    #[allow(unused)]
    pub fn mechanisms(&self) -> &Mutex<HashMap<HashableMechanismType, MechanismInfo>> {
        &self.mechanisms
    }
}

impl Pkcs11Pool {
    fn limit_to_string(limit: Limit) -> Option<String> {
        match limit {
            Limit::Max(v) => Some(format!("{v}")),
            Limit::Unavailable => None,
            Limit::Infinite => Some("Infinite".to_string()),
        }
    }

    fn log_info_prop(desc: &'static str, prop: impl Display) {
        info!("{desc}: {prop}");
    }

    fn log_crit_prop(desc: &'static str, prop: bool) {
        if prop {
            warn!("{desc:}: {prop}");
        }
    }

    fn log_debug_prop(desc: &'static str, prop: impl Display) {
        debug!("{desc}: {prop}");
    }

    fn log_opt_debug_prop(desc: &'static str, prop: Option<impl Display>) {
        if let Some(prop) = prop {
            debug!("{desc:}: {prop}");
        }
    }

    fn log_token_info_properties(token_info: &TokenInfo) {
        Self::log_info_prop("Token label", token_info.label());
        Self::log_info_prop("Token manufacturer id", token_info.manufacturer_id());
        Self::log_info_prop("Token model", token_info.model());
        Self::log_debug_prop("Token serial number", token_info.serial_number());
        Self::log_info_prop("Token hardware version", token_info.hardware_version());
        Self::log_info_prop("Token firmware version", token_info.firmware_version());
        Self::log_info_prop("Token login required", token_info.login_required());
        Self::log_crit_prop("Token in error state", token_info.error_state());
        Self::log_crit_prop("Token write protected", token_info.write_protected());
        Self::log_crit_prop("Token not initialized", !token_info.token_initialized());
        Self::log_crit_prop("Token user pin final try", token_info.user_pin_final_try());
        Self::log_crit_prop("Token user pin locked", token_info.user_pin_locked());
        Self::log_debug_prop("Token user pin count low", token_info.user_pin_count_low());
        Self::log_crit_prop(
            "Token user pin to be changed",
            token_info.user_pin_to_be_changed(),
        );
        Self::log_debug_prop(
            "Token user pin initialized",
            token_info.user_pin_initialized(),
        );
        Self::log_crit_prop(
            "Token security officer pin locked",
            token_info.so_pin_locked(),
        );
        Self::log_crit_prop(
            "Token security pin final try",
            token_info.so_pin_final_try(),
        );
        Self::log_crit_prop(
            "Token security pin to be changed",
            token_info.so_pin_to_be_changed(),
        );
        Self::log_debug_prop(
            "Token security pin count low",
            token_info.so_pin_count_low(),
        );
        Self::log_debug_prop("Token has random generator", token_info.rng());
        Self::log_debug_prop("Token has clock", token_info.clock_on_token());
        Self::log_debug_prop(
            "Token has protected authentication path",
            token_info.protected_authentication_path(),
        );
        Self::log_debug_prop(
            "Token restore key not needed",
            token_info.restore_key_not_needed(),
        );
        Self::log_debug_prop(
            "Token supports dual crypto operations",
            token_info.dual_crypto_operations(),
        );
        Self::log_opt_debug_prop(
            "Token max session count",
            Self::limit_to_string(token_info.max_session_count()),
        );
        Self::log_opt_debug_prop(
            "Token max r/w session count",
            Self::limit_to_string(token_info.max_rw_session_count()),
        );
        Self::log_opt_debug_prop("Token r/w session count", token_info.rw_session_count());
        Self::log_debug_prop("Token min pin length", token_info.min_pin_length());
        Self::log_debug_prop("Token max pin length", token_info.max_pin_length());
        Self::log_opt_debug_prop(
            "Token total public memory",
            token_info.total_public_memory(),
        );
        Self::log_opt_debug_prop("Token free public memory", token_info.free_public_memory());
        Self::log_opt_debug_prop(
            "Token total private memory",
            token_info.total_private_memory(),
        );
        Self::log_opt_debug_prop(
            "Token free private memory",
            token_info.free_private_memory(),
        );
        Self::log_opt_debug_prop(
            "Token UTC time",
            token_info.utc_time().map(|t| t.as_iso8601_string()),
        );
    }

    fn log_mechanisms(mechanisms: &HashMap<HashableMechanismType, MechanismInfo>) {
        let names = mechanisms
            .keys()
            .map(|&typ| (format!("{typ}"), typ))
            .collect::<HashMap<String, HashableMechanismType>>();

        let mut sorted_names = names.keys().map(ToOwned::to_owned).collect::<Vec<String>>();

        sorted_names.sort_unstable();

        for name in sorted_names {
            let mech_typ = names.get(&name).unwrap();
            let mech_info = mechanisms.get(mech_typ).unwrap();

            let mut flags = vec![];
            if mech_info.hardware() {
                flags.push("hw");
            }
            if mech_info.generate_key_pair() {
                flags.push("generate");
            }
            if mech_info.sign() {
                flags.push("sign");
            }
            if mech_info.ec_from_parameters() {
                flags.push("params");
            }
            if mech_info.ec_from_oid() {
                flags.push("oid");
            }
            if mech_info.ec_compressed() {
                flags.push("compressed");
            }
            if mech_info.ec_uncompressed() {
                flags.push("uncompressed");
            }
            let flags = flags.join(",");

            info!(
                "Token supports mechanism: {name} (min key size={}, max key size={}, flags=[{flags}])",
                mech_info.min_key_size(),
                mech_info.max_key_size()
            );
        }
    }
}

fn max_token_concurrency(pkcs11: &Pkcs11, slot: Slot) -> Result<Option<u32>, Error> {
    let token_info = pkcs11.get_token_info(slot)?;
    if let Limit::Max(v) = token_info.max_rw_session_count()
        && let Ok(v) = u32::try_from(v)
    {
        return Ok(Some(v));
    }
    Ok(None)
}

fn max_os_concurrency() -> Option<u32> {
    if let Ok(v) = available_parallelism()
        && let Ok(v) = u32::try_from(v.get())
    {
        return Some(v);
    }
    None
}

impl Deref for Pkcs11Pool {
    type Target = r2d2::Pool<Pkcs11ConnectionManager>;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

pub struct Pkcs11ConnectionManager {
    /// The PKCS#11 context.
    ///
    /// Used to create sessions, login and to query token information.
    pkcs11: Pkcs11,

    /// The slot which connections to the HSM use.
    slot: Slot,

    /// Information about the token to which this slot belongs.
    token_info: Arc<TokenInfo>,

    /// Information about the slot which this pool is for.
    slot_info: Arc<SlotInfo>,

    // The set of algorithms (mechanisms in PKCS#11 speak) supported by this
    // "slot" as reported by the PKCS#11 C_GetMechanismList API.
    mechanisms: Arc<Mutex<HashMap<HashableMechanismType, MechanismInfo>>>,
}

impl Pkcs11ConnectionManager {
    pub fn new(
        pkcs11: Pkcs11,
        slot: Slot,
        token_info: Arc<TokenInfo>,
        slot_info: Arc<SlotInfo>,
        mechanisms: Arc<Mutex<HashMap<HashableMechanismType, MechanismInfo>>>,
    ) -> Self {
        Self {
            pkcs11,
            slot,
            token_info,
            slot_info,
            mechanisms,
        }
    }

    #[allow(unused)]
    pub fn token_info(&self) -> &TokenInfo {
        &self.token_info
    }

    #[allow(unused)]
    pub fn slot_info(&self) -> &SlotInfo {
        &self.slot_info
    }

    #[allow(unused)]
    pub fn mechanisms(&self) -> &Mutex<HashMap<HashableMechanismType, MechanismInfo>> {
        &self.mechanisms
    }
}

pub struct PoolConnection {
    /// The PKCS#11 session through which functions can be invoked.
    session: Session,

    /// A cache of PKCS#11 object handles for this session.
    ///
    /// Note: Cannot be shared across all connections of the pool due to the
    /// PKCS#11 specification where it says:
    ///
    ///   "When an object is created or found on a token by an application,
    ///    Cryptoki assigns it an object handle for that application’s
    ///    sessions to use to access it.  A particular object on a token does
    ///    not necessarily have a handle which is fixed for the lifetime of
    ///    the object; however, if a particular session can use a particular
    ///    handle to access a particular object, then that session will
    ///    continue to be able to use that handle to access that object as
    ///    long as the session continues to exist, the object continues to
    ///    exist, and the object continues to be accessible to the session."
    ///
    /// From https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html#_Toc416959689
    handle_cache: HandleCache,

    /// The PKCS#11 slot this session relates to.
    slot_info: Arc<SlotInfo>,

    /// The PKCS#11 token this session relates to.
    token_info: Arc<TokenInfo>,

    /// Cached information about the algorithms supported by this token.
    mechanisms: Arc<Mutex<HashMap<HashableMechanismType, MechanismInfo>>>,
}

impl PoolConnection {
    pub fn new(
        session: Session,
        slot_info: Arc<SlotInfo>,
        token_info: Arc<TokenInfo>,
        mechanisms: Arc<Mutex<HashMap<HashableMechanismType, MechanismInfo>>>,
    ) -> Self {
        Self {
            session,
            handle_cache: HandleCache::new(100),
            slot_info,
            token_info,
            mechanisms,
        }
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn handle_cache(&self) -> &HandleCache {
        &self.handle_cache
    }

    pub fn ensure_logged_in(&self, pool: &Pkcs11Pool, pin: AuthPin) -> Result<(), Error> {
        if self.session.get_session_info()?.session_state() != SessionState::RwUser {
            if pool.user_pin_final_try()? {
                let reason = "Cowardly refusing to login as PKCS#11 reports that the next failed login attempt will lock the token".to_string();
                warn!(reason);
                return Err(Error::UnusableConfig(reason));
            } else {
                self.session.login(UserType::User, Some(&pin))?;
            }
        }
        Ok(())
    }

    #[allow(unused)]
    pub fn slot_info(&self) -> &SlotInfo {
        &self.slot_info
    }

    #[allow(unused)]
    pub fn token_info(&self) -> &TokenInfo {
        &self.token_info
    }

    pub fn mechanisms(&self) -> &Mutex<HashMap<HashableMechanismType, MechanismInfo>> {
        &self.mechanisms
    }
}

impl ManageConnection for Pkcs11ConnectionManager {
    type Connection = PoolConnection;

    type Error = cryptoki::error::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let session = self.pkcs11.open_rw_session(self.slot)?;
        Ok(PoolConnection::new(
            session,
            self.slot_info.clone(),
            self.token_info.clone(),
            self.mechanisms.clone(),
        ))
    }

    fn is_valid(&self, conn: &mut PoolConnection) -> Result<(), Self::Error> {
        debug!("Testing session validity");
        match conn.session().get_session_info().is_ok() {
            true => Ok(()),
            false => {
                debug!("Session is no longer valid (not logged in as a R/W user");
                Err(Self::Error::Pkcs11(
                    RvError::UserNotLoggedIn,
                    Function::GetSessionInfo,
                ))
            }
        }
    }

    fn has_broken(&self, _conn: &mut Self::Connection) -> bool {
        false
    }
}
