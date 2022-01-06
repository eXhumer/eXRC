#ifndef REDDIT_SERVICE_HXX
#define REDDIT_SERVICE_HXX

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QOAuth2AuthorizationCodeFlow>
#include <QOAuthHttpServerReplyHandler>

class RedditAuthorizationData;

namespace eXRC::Service {
class Reddit : public QObject {
  Q_OBJECT

private:
  RedditAuthorizationData *m_authData;
  QNetworkAccessManager *m_nam;
  QOAuthHttpServerReplyHandler *m_replyHandler;
  QOAuth2AuthorizationCodeFlow *m_authFlow;

public:
  Reddit(QString clientId, QString token, QDateTime expAt,
         QString refreshToken = QString(), QNetworkAccessManager *nam = nullptr,
         QObject *parent = nullptr);
  Reddit(QString clientId, QNetworkAccessManager *nam = nullptr,
         QObject *parent = nullptr);

private slots:
  void onGranted();
  void onTokenExpiry();

public slots:
  void grant(bool permanent);
  void revoke();

signals:
  void granted();
  void grantError(const QString &error, const QString &errorDescription,
                  const QUrl &uri);
  void grantExpired();
  void revoked();
  void revokeError(const QNetworkReply::NetworkError &error,
                   const QString &errorString);
};
} // namespace eXRC::Service

#endif // REDDIT_SERVICE_HXX
