#include "LibConfig.hxx"
#include "Reddit.hxx"
#include "RedditAuthorizationData.hxx"
#include <QAuthenticator>
#include <QDesktopServices>
#include <QUrlQuery>

// Service is hardcoded to use http://localhost:65010/auth_callback as
// authorization callback
namespace eXRC::Service {
Reddit::Reddit(QString clientId, QNetworkAccessManager *nam, QString token,
               QDateTime expAt, QString refreshToken, QObject *parent)
    : Reddit(clientId, nam, parent) {
  m_authData->setToken(token);
  m_authData->setRefreshToken(refreshToken);
  m_authData->setExpirationAt(expAt);
}

Reddit::Reddit(QString clientId, QNetworkAccessManager *nam, QObject *parent)
    : QObject(parent) {
  m_nam = nam;
  m_authData = new RedditAuthorizationData;
  m_authFlow = new QOAuth2AuthorizationCodeFlow;
  m_authFlow->setAccessTokenUrl(
      QUrl("https://www.reddit.com/api/v1/access_token"));
  m_authFlow->setAuthorizationUrl(
      QUrl("https://www.reddit.com/api/v1/authorize"));
  m_authFlow->setClientIdentifier(clientId);
  m_authFlow->setScope("identity");
  m_authFlow->setUserAgent(LIB_NAME "/" LIB_VERSION);
  m_replyHandler = new QOAuthHttpServerReplyHandler(65010);
  m_replyHandler->setCallbackPath("auth_callback");
  m_authFlow->setReplyHandler(m_replyHandler);

  connect(m_authFlow, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser,
          &QDesktopServices::openUrl);
  connect(m_authFlow, &QOAuth2AuthorizationCodeFlow::granted, this,
          &Reddit::onGranted);
  connect(m_authFlow, &QOAuth2AuthorizationCodeFlow::error, this,
          &Reddit::grantError);
}

void Reddit::onGranted() {
  m_authData->setExpirationAt(m_authFlow->expirationAt());
  m_authData->setRefreshToken(m_authFlow->refreshToken());
  m_authData->setToken(m_authFlow->token());
  emit this->granted();
}

void Reddit::onTokenExpiry() {
  if (!m_authData->refreshToken().isEmpty()) {
    m_authFlow->setRefreshToken(m_authData->refreshToken());
    m_authFlow->refreshAccessToken();
    return;
  }

  emit this->grantExpired();
}

void Reddit::grant(bool permanent) {
  m_authFlow->setModifyParametersFunction(
      [this, permanent](QAbstractOAuth::Stage stage,
                        QMultiMap<QString, QVariant> *parameters) {
        if (stage == QAbstractOAuth::Stage::RequestingAuthorization &&
            permanent)
          parameters->insert("duration", "permanent");
      });

  m_authFlow->grant();
}

void Reddit::revoke() {
  if (!m_authFlow->token().isEmpty()) {
    QUrlQuery revokeData;
    revokeData.addQueryItem("token", m_authData->token());
    revokeData.addQueryItem("token_token_hint", "access_token");

    QNetworkReply *res = m_authFlow->networkAccessManager()->post(
        QNetworkRequest(QUrl("https://www.reddit.com/api/v1/revoke_token")),
        revokeData.toString(QUrl::FullyEncoded).toUtf8());

    connect(m_authFlow->networkAccessManager(),
            &QNetworkAccessManager::authenticationRequired, this,
            [this, res](QNetworkReply *reply, QAuthenticator *authenticator) {
              if (res == reply) {
                authenticator->setUser(m_authFlow->clientIdentifier());
                authenticator->setPassword("");
              }
            });

    connect(res, &QNetworkReply::finished, this, [this, res]() {
      if (res->error() != QNetworkReply::NoError) {
        emit this->revokeError(res->errorString());
        return;
      }

      m_authData->setExpirationAt(QDateTime());
      m_authData->setToken(QString());

      if (!m_authData->refreshToken().isEmpty()) {
        QUrlQuery revokeData;
        revokeData.addQueryItem("token", m_authData->refreshToken());
        revokeData.addQueryItem("token_token_hint", "refresh_token");

        QNetworkReply *res = m_authFlow->networkAccessManager()->post(
            QNetworkRequest(QUrl("https://www.reddit.com/api/v1/revoke_token")),
            revokeData.toString(QUrl::FullyEncoded).toUtf8());

        connect(
            m_authFlow->networkAccessManager(),
            &QNetworkAccessManager::authenticationRequired, this,
            [this, res](QNetworkReply *reply, QAuthenticator *authenticator) {
              if (res == reply) {
                authenticator->setUser(m_authFlow->clientIdentifier());
                authenticator->setPassword("");
              }
            });

        connect(res, &QNetworkReply::finished, this, [this, res]() {
          if (res->error() != QNetworkReply::NoError) {
            emit this->revokeError(res->errorString());
            return;
          }

          m_authData->setRefreshToken(QString());
          emit this->revoked();
        });

      } else
        emit this->revoked();
    });
  }
}
} // namespace eXRC::Service
