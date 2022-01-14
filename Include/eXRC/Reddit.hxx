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

#ifndef REDDIT_SERVICE_HXX
#define REDDIT_SERVICE_HXX

#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QOAuth2AuthorizationCodeFlow>
#include <QOAuthHttpServerReplyHandler>

class AuthorizationData;

namespace eXRC::Service {
class Reddit : public QObject {
  Q_OBJECT

private:
  static QString baseUrl;
  static QString oauthUrl;
  AuthorizationData *m_authData;
  QNetworkAccessManager *m_nam;
  QOAuthHttpServerReplyHandler *m_replyHandler;
  QOAuth2AuthorizationCodeFlow *m_authFlow;
  QJsonObject m_idenJsonObj;

public:
  Reddit(QString clientId, QNetworkAccessManager *nam, QString token,
         QDateTime expAt, QString refreshToken = QString(),
         QObject *parent = nullptr);
  Reddit(QString clientId, QNetworkAccessManager *nam = nullptr,
         QObject *parent = nullptr);
  QString token() const;
  QString refreshToken() const;
  QDateTime expirationAt() const;
  bool expired() const;

private slots:
  void authenticatedPostUrl(const QString &url, const QString &title,
                            const QString &subreddit, const QString &flairId,
                            bool sendReplies, bool nsfw, bool spoiler);
  void fetchIdentity();
  void onGranted();
  void onTokenExpiry();

public slots:
  void grant(bool permanent);
  void postUrl(const QString &url, const QString &title,
               const QString &subreddit, const QString &flairId,
               bool sendReplies, bool nsfw, bool spoiler);
  void revoke();

signals:
  void identityFetchError(const QString &error);
  void grantError(const QString &error);
  void grantExpired();
  void postedUrl(const QString &postUrl, const QString &redditUrl);
  void postUrlError(const QString &postUrl, const QString &error);
  void ready(const QJsonObject &identity);
  void revoked();
  void revokeError(const QString &error);
};
} // namespace eXRC::Service

#endif // REDDIT_SERVICE_HXX
