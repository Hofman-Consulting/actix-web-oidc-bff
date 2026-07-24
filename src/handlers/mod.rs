/// `GET /auth/callback` — exchanges the authorization code, validates the
/// ID token, and establishes the session.
pub mod callback;
/// `GET /auth/login` — begins the OIDC authorization-code + PKCE flow.
pub mod login;
/// `POST /auth/logout` — purges the session and revokes tokens.
pub mod logout;
/// `GET /auth/me` — returns the current session's identity claims.
pub mod me;
