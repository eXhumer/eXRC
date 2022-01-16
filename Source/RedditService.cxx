/*
 * eXRC - Reddit communication layer via Qt
 * Copyright (C) 2021 - eXhumer
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "AuthorizationData.hxx"
#include "LibConfig.hxx"
#include "Reddit.hxx"
#include <QAuthenticator>
#include <QDesktopServices>
#include <QFile>
#include <QFileInfo>
#include <QHttpMultiPart>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMimeDatabase>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QOAuth2AuthorizationCodeFlow>
#include <QOAuthHttpServerReplyHandler>
#include <QUrlQuery>
#include <QWebSocket>

namespace eXRC::Service {
QString Reddit::baseUrl("https://www.reddit.com");
QString Reddit::oauthUrl("https://oauth.reddit.com");

QNetworkReply *Reddit::submitMedia(const QString *mediaUrl,
                                   const QString &title,
                                   const QString &subreddit,
                                   const QString &flairId, bool sendReplies,
                                   bool nsfw, bool spoiler,
                                   QString *thumbnailUrl) {
  QUrlQuery postData{
      {"api_type", "json"},
      {"kind", thumbnailUrl == nullptr ? "image" : "video"},
      {"nsfw", nsfw ? "true" : "false"},
      {"sendreplies", sendReplies ? "true" : "false"},
      {"spoiler", spoiler ? "true" : "false"},
      {"title", title},
      {"url", *mediaUrl},
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

  if (thumbnailUrl != nullptr)
    postData.addQueryItem("video_poster_url", *thumbnailUrl);

  QUrl postUrl(oauthUrl + "/api/submit");
  postUrl.setQuery(QUrlQuery{
      {"raw_json", "1"},
      {"resubmit", "true"},
  });
  QNetworkRequest postReq(postUrl);
  postReq.setRawHeader("Authorization", ("bearer " + token()).toUtf8());

  return m_nam->post(postReq, postData.toString(QUrl::FullyEncoded).toUtf8());
}

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

void Reddit::authenticatedPostMedia(QFile *mediaFile, QFile *videoThumbnailFile,
                                    const QString &title,
                                    const QString &subreddit,
                                    const QString &flairId, bool sendReplies,
                                    bool nsfw, bool spoiler) {
  QString mediaMimeType =
      QMimeDatabase().mimeTypeForFile(QFileInfo(*mediaFile).fileName()).name();

  if (!(mediaMimeType.startsWith("image/") ||
        mediaMimeType.startsWith("video/"))) {
    emit this->postMediaError(mediaFile, videoThumbnailFile,
                              "Unsupported media file mimetype! Only "
                              "supports image and video files!");
    return;
  }

  if (mediaMimeType.startsWith("video/") and videoThumbnailFile == nullptr)
    videoThumbnailFile = new QFile(":/VideoPoster.png");

  if (mediaMimeType.startsWith("video/")) {
    QString *mediaUrl = new QString;
    QString *thumbnailUrl = new QString;
    QObject *videoCtx = new QObject;

    connect(
        this, &Reddit::mediaUploaded, videoCtx,
        [this, flairId, mediaFile, mediaUrl, nsfw, sendReplies, spoiler,
         subreddit, thumbnailUrl, title, videoCtx, videoThumbnailFile](
            QFile *uploadedFile, const QString &url, const QString &assetId) {
          if (uploadedFile == mediaFile || uploadedFile == videoThumbnailFile) {
            if (uploadedFile == videoThumbnailFile) {
              *thumbnailUrl = url;

              if (mediaUrl->isNull())
                return;
            } else {
              *mediaUrl = url;

              if (thumbnailUrl->isNull())
                return;
            }

            QNetworkReply *submitResp =
                submitMedia(mediaUrl, title, subreddit, flairId, sendReplies,
                            nsfw, spoiler, thumbnailUrl);

            connect(
                submitResp, &QNetworkReply::finished, videoCtx,
                [this, mediaFile, submitResp, videoCtx, videoThumbnailFile]() {
                  if (submitResp->error() != QNetworkReply::NoError) {

                    emit this->postMediaError(mediaFile, videoThumbnailFile,
                                              submitResp->errorString());
                    videoCtx->deleteLater();
                    return;
                  }

                  QString uploadWebSocketUrl =
                      QJsonDocument::fromJson(submitResp->readAll())
                          .object()["json"]
                          .toObject()["data"]
                          .toObject()["websocket_url"]
                          .toString();

                  QObject *wsCtx = new QObject;
                  QWebSocket *mediaWS = new QWebSocket(
                      QString(), QWebSocketProtocol::VersionLatest, wsCtx);
                  connect(
                      mediaWS, &QWebSocket::connected, wsCtx,
                      [this, mediaFile, mediaWS, videoThumbnailFile, wsCtx]() {
                        connect(mediaWS, &QWebSocket::textMessageReceived,
                                wsCtx,
                                [this, mediaFile, mediaWS, videoThumbnailFile,
                                 wsCtx](const QString &message) {
                                  QJsonObject wsMsg =
                                      QJsonDocument::fromJson(message.toUtf8())
                                          .object();

                                  mediaWS->close();

                                  if (wsMsg["type"].toString() == "failed") {
                                    emit this->postMediaError(
                                        mediaFile, videoThumbnailFile,
                                        QString(QJsonDocument(wsMsg).toJson(
                                            QJsonDocument::Indented)));
                                    wsCtx->deleteLater();
                                    return;
                                  }

                                  emit this->postedMedia(
                                      mediaFile, videoThumbnailFile,
                                      wsMsg["payload"]
                                          .toObject()["redirect"]
                                          .toString());
                                  wsCtx->deleteLater();
                                });
                      });
                  mediaWS->open(QUrl(uploadWebSocketUrl));
                  videoCtx->deleteLater();
                });

            connect(submitResp, &QNetworkReply::finished, submitResp,
                    &QNetworkReply::deleteLater);
          }
        });

    connect(this, &Reddit::mediaUploadError, videoCtx,
            [mediaFile, videoCtx, videoThumbnailFile](QFile *failedMediaFile,
                                                      const QString &error) {
              if (failedMediaFile == mediaFile ||
                  failedMediaFile == videoThumbnailFile)
                videoCtx->deleteLater();
            });

    uploadMedia(videoThumbnailFile);
    uploadMedia(mediaFile);
  } else {
    QObject *imageCtx = new QObject;

    connect(
        this, &Reddit::mediaUploaded, imageCtx,
        [this, flairId, imageCtx, mediaFile, nsfw, sendReplies, spoiler,
         subreddit, title](QFile *uploadedFile, const QString &mediaUrl,
                           const QString &assetId) {
          if (uploadedFile == mediaFile) {
            QNetworkReply *submitResp =
                submitMedia(&mediaUrl, title, subreddit, flairId, sendReplies,
                            nsfw, spoiler);

            connect(
                submitResp, &QNetworkReply::finished, imageCtx,
                [this, mediaFile, submitResp, imageCtx]() {
                  if (submitResp->error() != QNetworkReply::NoError) {

                    emit this->postMediaError(mediaFile, nullptr,
                                              submitResp->errorString());
                    imageCtx->deleteLater();
                    return;
                  }

                  QString uploadWebSocketUrl =
                      QJsonDocument::fromJson(submitResp->readAll())
                          .object()["json"]
                          .toObject()["data"]
                          .toObject()["websocket_url"]
                          .toString();

                  QObject *wsCtx = new QObject;
                  QWebSocket *mediaWS = new QWebSocket(
                      QString(), QWebSocketProtocol::VersionLatest, wsCtx);
                  connect(
                      mediaWS, &QWebSocket::connected, wsCtx,
                      [this, mediaFile, mediaWS, wsCtx]() {
                        connect(
                            mediaWS, &QWebSocket::binaryMessageReceived, wsCtx,
                            [this, mediaFile, mediaWS,
                             wsCtx](const QByteArray &message) {
                              QJsonObject wsMsg =
                                  QJsonDocument::fromJson(message).object();

                              mediaWS->close();

                              if (wsMsg["type"].toString() == "failed") {
                                emit this->postMediaError(
                                    mediaFile, nullptr,
                                    QString(QJsonDocument(wsMsg).toJson(
                                        QJsonDocument::Indented)));
                                wsCtx->deleteLater();
                                return;
                              }

                              emit this->postedMedia(mediaFile, nullptr,
                                                     wsMsg["payload"]
                                                         .toObject()["redirect"]
                                                         .toString());
                              wsCtx->deleteLater();
                            });
                      });

                  mediaWS->open(QUrl(uploadWebSocketUrl));
                  imageCtx->deleteLater();
                });

            connect(submitResp, &QNetworkReply::finished, submitResp,
                    &QNetworkReply::deleteLater);
          }
        });

    connect(
        this, &Reddit::mediaUploadError, imageCtx,
        [mediaFile, imageCtx](QFile *failedMediaFile, const QString &error) {
          if (failedMediaFile == mediaFile)
            imageCtx->deleteLater();
        });

    uploadMedia(mediaFile);
  }
}

void Reddit::authenticatedPostUrl(const QString &url, const QString &title,
                                  const QString &subreddit,
                                  const QString &flairId, bool sendReplies,
                                  bool nsfw, bool spoiler) {
  QUrlQuery postData{
      {"api_type", "json"},
      {"kind", "link"},
      {"nsfw", nsfw ? "true" : "false"},
      {"sendreplies", sendReplies ? "true" : "false"},
      {"spoiler", spoiler ? "true" : "false"},
      {"title", title},
      {"url", url},
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

  connect(postResp, &QNetworkReply::finished, this, [this, postResp, url]() {
    if (postResp->error() != QNetworkReply::NoError) {
      emit this->postUrlError(url, postResp->errorString());
      return;
    }

    QJsonObject obj = QJsonDocument::fromJson(postResp->readAll()).object();
    QString redditUrl =
        obj["json"].toObject()["data"].toObject()["url"].toString();

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

void Reddit::uploadMedia(QFile *mediaFile) {
  QString mediaFileName = QFileInfo(*mediaFile).fileName();
  QString mediaMimeType = QMimeDatabase().mimeTypeForFile(mediaFileName).name();

  QNetworkRequest postAssetDataReq(QUrl(oauthUrl + "/api/media/asset"));
  postAssetDataReq.setRawHeader("Authorization",
                                ("bearer " + token()).toUtf8());

  QNetworkReply *postAssetDataRes =
      m_nam->post(postAssetDataReq, QUrlQuery{{"filepath", mediaFileName},
                                              {"mimetype", mediaMimeType}}
                                        .toString(QUrl::FullyEncoded)
                                        .toUtf8());

  QObject *uploadCtx = new QObject;
  connect(
      postAssetDataRes, &QNetworkReply::finished, uploadCtx,
      [this, mediaFile, mediaFileName, mediaMimeType, postAssetDataRes,
       uploadCtx]() {
        if (postAssetDataRes->error() != QNetworkReply::NoError) {
          emit this->mediaUploadError(mediaFile,
                                      postAssetDataRes->errorString());
          uploadCtx->deleteLater();
          return;
        }

        QJsonObject assetUploadCredential =
            QJsonDocument::fromJson(postAssetDataRes->readAll()).object();
        QString uploadAction =
            assetUploadCredential["args"].toObject()["action"].toString();
        QJsonArray uploadFields =
            assetUploadCredential["args"].toObject()["fields"].toArray();
        QString uploadAssetId =
            assetUploadCredential["asset"].toObject()["asset_id"].toString();

        QHttpMultiPart *uploadMultiPart =
            new QHttpMultiPart(QHttpMultiPart::FormDataType);
        QString uploadKey;

        for (const auto &field : uploadFields) {
          QJsonObject fieldObj = field.toObject();

          if (fieldObj["name"].toString() == "key")
            uploadKey = fieldObj["value"].toString();

          QHttpPart fieldPart;
          fieldPart.setHeader(QNetworkRequest::ContentDispositionHeader,
                              QVariant("form-data; name=\"" +
                                       fieldObj["name"].toString() + "\""));
          fieldPart.setBody(fieldObj["value"].toString().toUtf8());
          uploadMultiPart->append(fieldPart);
        }

        QHttpPart videoFilePart;
        videoFilePart.setHeader(QNetworkRequest::ContentTypeHeader,
                                QVariant(mediaMimeType));
        videoFilePart.setHeader(
            QNetworkRequest::ContentDispositionHeader,
            QVariant("form-data; name=\"file\"; filename=\"" + mediaFileName +
                     "\""));
        mediaFile->open(QIODevice::ReadOnly);
        videoFilePart.setBodyDevice(mediaFile);
        mediaFile->setParent(uploadMultiPart);
        uploadMultiPart->append(videoFilePart);

        QNetworkRequest uploadReq(QUrl("https:" + uploadAction));
        QNetworkReply *uploadRes = m_nam->post(uploadReq, uploadMultiPart);
        connect(uploadRes, &QNetworkReply::uploadProgress, this,
                [this, mediaFile](qint64 bytesSent, qint64 bytesTotal) {
                  emit this->mediaUploadProgress(mediaFile, bytesSent,
                                                 bytesTotal);
                });
        connect(uploadRes, &QNetworkReply::finished, this,
                [this, mediaFile, uploadAction, uploadAssetId, uploadKey,
                 uploadRes]() {
                  if (uploadRes->error() != QNetworkReply::NoError) {
                    emit this->mediaUploadError(mediaFile,
                                                uploadRes->errorString());
                    return;
                  }

                  emit this->mediaUploaded(
                      mediaFile, "https:" + uploadAction + "/" + uploadKey,
                      uploadAssetId);
                });
        connect(uploadRes, &QNetworkReply::finished, uploadRes,
                &QNetworkReply::deleteLater);
      });
  connect(postAssetDataRes, &QNetworkReply::finished, postAssetDataRes,
          &QNetworkReply::deleteLater);
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

void Reddit::postMedia(QFile *mediaFile, QFile *videoThumbnailFile,
                       const QString &title, const QString &subreddit,
                       const QString &flairId, bool sendReplies, bool nsfw,
                       bool spoiler) {
  if (!expired())
    authenticatedPostMedia(mediaFile, videoThumbnailFile, title, subreddit,
                           flairId, sendReplies, nsfw, spoiler);

  else {
    QObject *postCtx = new QObject;
    connect(
        this, &Reddit::ready, postCtx,
        [this, flairId, mediaFile, nsfw, postCtx, sendReplies, spoiler,
         subreddit, title, videoThumbnailFile](const QJsonObject &identity) {
          authenticatedPostMedia(mediaFile, videoThumbnailFile, title,
                                 subreddit, flairId, sendReplies, nsfw,
                                 spoiler);
          postCtx->deleteLater();
        },
        Qt::UniqueConnection);
    connect(
        this, &Reddit::grantExpired, postCtx, [postCtx]() { delete postCtx; },
        Qt::UniqueConnection);

    onTokenExpiry();
  }
}

void Reddit::postUrl(const QString &url, const QString &title,
                     const QString &subreddit, const QString &flairId,
                     bool sendReplies, bool nsfw, bool spoiler) {
  if (!expired())
    authenticatedPostUrl(url, title, subreddit, flairId, sendReplies, nsfw,
                         spoiler);

  else {
    QObject *postCtx = new QObject;
    connect(
        this, &Reddit::ready, postCtx,
        [this, postCtx, url, title, subreddit, flairId, sendReplies, nsfw,
         spoiler](const QJsonObject &identity) {
          authenticatedPostUrl(url, title, subreddit, flairId, sendReplies,
                               nsfw, spoiler);
          postCtx->deleteLater();
        },
        Qt::UniqueConnection);
    connect(
        this, &Reddit::grantExpired, postCtx, [postCtx]() { delete postCtx; },
        Qt::UniqueConnection);

    onTokenExpiry();
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
