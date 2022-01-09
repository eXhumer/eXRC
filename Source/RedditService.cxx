#include "AuthorizationData.hxx"
#include "LibConfig.hxx"
#include "Reddit.hxx"
#include <QAuthenticator>
#include <QDesktopServices>
#include <QJsonDocument>
#include <QUrlQuery>

namespace eXRC::Service {
QString Reddit::baseUrl("https://www.reddit.com");
QString Reddit::oauthUrl("https://oauth.reddit.com");

Reddit::Reddit(QString clientId, QNetworkAccessManager *nam, QString token,
               QDateTime expAt, QString refreshToken, QObject *parent)
    : Reddit(clientId, nam, parent) {
  m_authData->setToken(token);
  m_authData->setRefreshToken(refreshToken);
  m_authData->setExpirationAt(expAt);

  if (expired())
    onTokenExpiry();

  else
    fetchIdentity();
}

Reddit::Reddit(QString clientId, QNetworkAccessManager *nam, QObject *parent)
    : QObject(parent) {
  m_nam = nam;
  m_authData = new AuthorizationData;
  m_replyHandler = new QOAuthHttpServerReplyHandler(65010);
  m_replyHandler->setCallbackPath("auth_callback");
  m_authFlow = new QOAuth2AuthorizationCodeFlow(m_nam);
  m_authFlow->setAccessTokenUrl(QUrl(baseUrl + "/api/v1/access_token"));
  m_authFlow->setAuthorizationUrl(QUrl(baseUrl + "/api/v1/authorize"));
  m_authFlow->setClientIdentifier(clientId);
  m_authFlow->setScope("identity submit");
  m_authFlow->setUserAgent(LIB_NAME "/" LIB_VERSION);
  m_authFlow->setReplyHandler(m_replyHandler);

  connect(m_authFlow, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser,
          &QDesktopServices::openUrl);
  connect(m_authFlow, &QOAuth2AuthorizationCodeFlow::granted, this,
          &Reddit::onGranted);
  connect(m_authFlow, &QOAuth2AuthorizationCodeFlow::error, this,
          [this](const QString &error, const QString &errorDesc,
                 const QUrl &uri) { emit this->grantError(error); });
}

QString Reddit::token() const { return m_authData->token(); }

QString Reddit::refreshToken() const { return m_authData->refreshToken(); }

QDateTime Reddit::expirationAt() const { return m_authData->expirationAt(); }

bool Reddit::expired() const { return m_authData->expired(); }

void Reddit::authenticatedPostUrl(const QString &url, const QString &title,
                                  const QString &subreddit,
                                  const QString &flairId) {
  QUrlQuery postData{
      {"api_json", "json"},           {"kind", "link"},     {"nsfw", "false"},
      {"sendreplies", "false"},       {"spoiler", "false"}, {"title", title},
      {"validate_on_submit", "true"},
  };

  if (!subreddit.isEmpty()) {
    postData.addQueryItem("sr", subreddit);
    postData.addQueryItem("submit_type", "subreddit");

    if (!flairId.isEmpty())
      postData.addQueryItem("flair_id", flairId);
  } else {
    postData.addQueryItem("sr", "u_" + m_idenJsonObj["name"].toString());
    postData.addQueryItem("submit_type", "profile");
  }

  QUrl postUrl(oauthUrl + "/api/submit");
  postUrl.setQuery(QUrlQuery{
      {"raw_json", "1"},
      {"resubmit", "true"},
  });
  QNetworkRequest postReq(postUrl);
  postReq.setRawHeader("Authorization", ("bearer " + token()).toUtf8());

  QNetworkReply *postResp =
      m_nam->post(postReq, postData.toString(QUrl::FullyEncoded).toUtf8());

  connect(postResp, &QNetworkReply::finished, this, [this, postResp, &url]() {
    if (postResp->error() != QNetworkReply::NoError) {
      emit this->postUrlError(url, postResp->errorString());
      return;
    }

    QString redditUrl = QJsonDocument::fromJson(postResp->readAll())
                            .object()["json"]
                            .toObject()["data"]
                            .toObject()["url"]
                            .toString();

    emit this->postedUrl(url, redditUrl);
  });
  connect(postResp, &QNetworkReply::finished, postResp,
          &QNetworkReply::deleteLater);
}

void Reddit::fetchIdentity() {
  QUrl meUrl(oauthUrl + "/api/v1/me");
  meUrl.setQuery(QUrlQuery{{"raw_json", "1"}});
  QNetworkRequest meReq(meUrl);
  meReq.setRawHeader("Authorization",
                     ("bearer " + m_authData->token()).toUtf8());
  QNetworkReply *meResp = m_nam->get(meReq);
  connect(meResp, &QNetworkReply::finished, this, [this, meResp]() {
    if (meResp->error() != QNetworkReply::NoError) {
      emit this->identityFetchError(meResp->errorString());
      return;
    }

    m_idenJsonObj = QJsonDocument::fromJson(meResp->readAll()).object();
    emit this->ready(m_idenJsonObj);
  });
  connect(meResp, &QNetworkReply::finished, meResp,
          &QNetworkReply::deleteLater);
}

void Reddit::onGranted() {
  m_authData->setExpirationAt(m_authFlow->expirationAt());
  m_authData->setRefreshToken(m_authFlow->refreshToken());
  m_authData->setToken(m_authFlow->token());
  fetchIdentity();
}

void Reddit::onTokenExpiry() {
  if (refreshToken().isEmpty())
    emit this->grantExpired();

  else {
    m_authFlow->setRefreshToken(refreshToken());
    m_authFlow->refreshAccessToken();
  }
}

void Reddit::grant(bool permanent) {
  if (expired() && refreshToken().isEmpty()) {
    m_authFlow->setModifyParametersFunction(
        [this, permanent](QAbstractOAuth::Stage stage,
                          QMultiMap<QString, QVariant> *parameters) {
          if (stage == QAbstractOAuth::Stage::RequestingAuthorization &&
              permanent)
            parameters->insert("duration", "permanent");
        });

    m_authFlow->grant();
  }
}

void Reddit::postUrl(const QString &url, const QString &title,
                     const QString &subreddit, const QString &flairId) {
  if (!expired())
    authenticatedPostUrl(url, title, subreddit, flairId);

  else {
    onTokenExpiry();

    QObject *postCtx = new QObject;
    connect(
        this, &Reddit::ready, postCtx,
        [this, postCtx, &url, &title, &subreddit,
         &flairId](const QJsonObject &identity) {
          authenticatedPostUrl(url, title, subreddit, flairId);
          postCtx->deleteLater();
        },
        Qt::UniqueConnection);
    connect(
        this, &Reddit::grantExpired, postCtx, [postCtx]() { delete postCtx; },
        Qt::UniqueConnection);
  }
}

void Reddit::revoke() {
  if (!refreshToken().isEmpty() || !token().isEmpty()) {
    QUrlQuery revokeData;
    revokeData.addQueryItem("token", refreshToken().isEmpty() ? token()
                                                              : refreshToken());
    revokeData.addQueryItem("token_token_hint", refreshToken().isEmpty()
                                                    ? "access_token"
                                                    : "refresh_token");

    QNetworkReply *res =
        m_nam->post(QNetworkRequest(QUrl(baseUrl + "/api/v1/revoke_token")),
                    revokeData.toString(QUrl::FullyEncoded).toUtf8());

    connect(m_nam, &QNetworkAccessManager::authenticationRequired, this,
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
      m_authData->setRefreshToken(QString());
      m_authData->setToken(QString());
      m_idenJsonObj = QJsonObject();

      emit this->revoked();
    });

    connect(res, &QNetworkReply::finished, res, &QNetworkReply::deleteLater);
  }

  else
    emit this->revokeError("No token available to revoke!");
}
} // namespace eXRC::Service
