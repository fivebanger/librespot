// Ported from librespot-java. Relicensed under MIT with permission.

// Known scopes:
//   ugc-image-upload, playlist-read-collaborative, playlist-modify-private,
//   playlist-modify-public, playlist-read-private, user-read-playback-position,
//   user-read-recently-played, user-top-read, user-modify-playback-state,
//   user-read-currently-playing, user-read-playback-state, user-read-private, user-read-email,
//   user-library-modify, user-library-read, user-follow-modify, user-follow-read, streaming,
//   app-remote-control

use std::time::{Duration, Instant};

use serde::Deserialize;
use thiserror::Error;

use crate::Error;

component! {
    TokenProvider : TokenProviderInner {
        tokens: Vec<Token> = vec![],
    }
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("no tokens available")]
    Empty,
}

impl From<TokenError> for Error {
    fn from(err: TokenError) -> Self {
        Error::unavailable(err)
    }
}

#[derive(Clone, Debug)]
pub struct Token {
    pub access_token: String,
    pub expires_in: Duration,
    pub token_type: String,
    pub scopes: Vec<String>,
    pub timestamp: Instant,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TokenData {
    access_token: String,
    expires_in: u64,
    token_type: String,
    scope: Vec<String>,
}

impl TokenProvider {
    fn find_token(&self, scopes: Vec<&str>) -> Option<usize> {
        self.lock(|inner| {
            (0..inner.tokens.len()).find(|&i| inner.tokens[i].in_scopes(scopes.clone()))
        })
    }

    // scopes must be comma-separated
    pub async fn get_token(&self, scopes: &str) -> Result<Token, Error> {
        let client_id = self.session().client_id();
        if client_id.is_empty() {
            return Err(Error::invalid_argument("Client ID cannot be empty"));
        }
        info!("Librespot requests a token, scopes: {:?}", scopes);

        if let Some(index) = self.find_token(scopes.split(',').collect()) {
            let cached_token = self.lock(|inner| inner.tokens[index].clone());
            if cached_token.is_expired() {
                self.lock(|inner| inner.tokens.remove(index));
            } else {
                info!("use a cached token");
                return Ok(cached_token);
            }
        }

        info!(
            "Requested token in scopes {:?} unavailable or expired, requesting new token.",
            scopes
        );

        info!("client_id = self.session().client_id(): {:#?}", client_id);
        //info!("device_id: {:#?}", self.session().device_id());
        //info!("query_uri: {:#?}", query_uri);

        let query_uri = format!(
            "hm://keymaster/token/authenticated?scope={}&client_id={}&device_id={}",
            scopes,
            client_id,
            self.session().device_id(),
        );

        let request = self.session().mercury().get(query_uri)?;
        let response = request.await?;
        let data = response.payload.first().ok_or(TokenError::Empty)?.to_vec();
        let token = Token::from_json(String::from_utf8(data)?)?;
        trace!("Got token: {:#?}", token);
        self.lock(|inner| inner.tokens.push(token.clone()));
        Ok(token)
    }

    // scopes must be comma-separated
    pub async fn get_token_user(&self, scopes: &str) -> Result<Token, Error> {
        let client_id = self.session().client_id();
        if client_id.is_empty() {
            return Err(Error::invalid_argument("Client ID cannot be empty"));
        }
        info!("User requests a token, client_id not hard coded, scopes: {:?}", scopes);

        if let Some(index) = self.find_token(scopes.split(',').collect()) {
            let cached_token = self.lock(|inner| inner.tokens[index].clone());
            if cached_token.is_expired() {
                self.lock(|inner| inner.tokens.remove(index));
            } else {
                info!("use a cached token");
                return Ok(cached_token);
            }
        }

        info!(
            "Requested token in scopes {:?} unavailable or expired, requesting new token.",
            scopes
        );

        info!("user, client_id = self.session().client_id(): {:#?}", client_id);
        //info!("user, device_id: {:#?}", self.session().device_id());
        //info!("user, query_uri: {:#?}", query_uri);

        let query_uri = format!(
            "hm://keymaster/token/authenticated?scope={}&client_id={}&device_id={}",
            scopes,
            client_id,
            self.session().device_id(),
        );

        let request = self.session().mercury().get(query_uri)?;
        let response = request.await?;
        let data = response.payload.first().ok_or(TokenError::Empty)?.to_vec();
        let token = Token::from_json(String::from_utf8(data)?)?;
        trace!("Got token: {:#?}", token);
        self.lock(|inner| inner.tokens.push(token.clone()));
        Ok(token)
    }

    pub async fn get_token_patch(&self, scopes: &str) -> Result<Token, Error> {
        let client_id = self.session().client_id();
        if client_id.is_empty() {
            return Err(Error::invalid_argument("Client ID cannot be empty"));
        }
        info!("User requests a token, client_id is hard coded, : {:?}", scopes);

        if let Some(index) = self.find_token(scopes.split(',').collect()) {
            let cached_token = self.lock(|inner| inner.tokens[index].clone());
            if cached_token.is_expired() {
                self.lock(|inner| inner.tokens.remove(index));
            } else {
                info!("use a cached token");
                return Ok(cached_token);
            }
        }

        info!(
            "Requested token in scopes {:?} unavailable or expired, requesting new token.",
            scopes
        );
        /*
        pub(crate) const KEYMASTER_CLIENT_ID: &str = "65b708073fc0480ea92a077233ca87bd";
        pub(crate) const ANDROID_CLIENT_ID: &str = "9a8d2f0ce77a4e248bb71fefcb557637";
        pub(crate) const IOS_CLIENT_ID: &str = "58bd3c95768941ea9eb4350aaa033eb3";
        */

        let client_id_patch: &str = "65b708073fc0480ea92a077233ca87bd";

        info!("patch, self.session().client_id(): {:#?}", client_id);
        info!("patch, client_id_patch = hard coded: {:#?}", client_id_patch);
        //info!("patch, device_id: {:#?}", self.session().device_id());
        //info!("patch, query_uri: {:#?}", query_uri);

        let query_uri = format!(
            "hm://keymaster/token/authenticated?scope={}&client_id={}&device_id={}",
            scopes,
            client_id_patch,
            self.session().device_id(),
        );

        let request = self.session().mercury().get(query_uri)?;
        let response = request.await?;
        let data = response.payload.first().ok_or(TokenError::Empty)?.to_vec();
        let token = Token::from_json(String::from_utf8(data)?)?;
        trace!("Got token: {:#?}", token);
        self.lock(|inner| inner.tokens.push(token.clone()));
        Ok(token)
    }
}

impl Token {
    const EXPIRY_THRESHOLD: Duration = Duration::from_secs(10);

    pub fn from_json(body: String) -> Result<Self, Error> {
        let data: TokenData = serde_json::from_slice(body.as_ref())?;
        Ok(Self {
            access_token: data.access_token,
            expires_in: Duration::from_secs(data.expires_in),
            token_type: data.token_type,
            scopes: data.scope,
            timestamp: Instant::now(),
        })
    }

    pub fn is_expired(&self) -> bool {
        self.timestamp + (self.expires_in.saturating_sub(Self::EXPIRY_THRESHOLD)) < Instant::now()
    }

    pub fn in_scope(&self, scope: &str) -> bool {
        for s in &self.scopes {
            if *s == scope {
                return true;
            }
        }
        false
    }

    pub fn in_scopes(&self, scopes: Vec<&str>) -> bool {
        for s in scopes {
            if !self.in_scope(s) {
                return false;
            }
        }
        true
    }
}
