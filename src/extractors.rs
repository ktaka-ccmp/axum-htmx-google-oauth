use crate::models::XCsrfToken;

#[async_trait]
impl<S> FromRequestParts<S> for XCsrfToken
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Error> {
        let x_csrf_token = parts
            .headers
            .get("x-csrf-token")
            .ok_or_else(|| reject::custom(Error::MissingXCsrfToken))?;
        Ok(XCsrfToken {
            token: x_csrf_token
                .to_str()
                .map_err(|_| Error::InvalidXCsrfToken)?
                .to_string(),
        })
    }
}
