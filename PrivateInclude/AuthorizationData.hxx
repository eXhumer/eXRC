#ifndef AUTHORIZATIONDATA_HXX
#define AUTHORIZATIONDATA_HXX

#include <QDateTime>
#include <QObject>
#include <QString>

class AuthorizationData : public QObject {
private:
  QDateTime m_expirationAt;
  QString m_refreshToken;
  QString m_token;

public:
  AuthorizationData(QDateTime expirationAt, QString token,
                    QString refreshToken = QString(),
                    QObject *parent = nullptr);
  AuthorizationData(QObject *parent = nullptr);
  bool expired() const;
  QDateTime expirationAt() const;
  QString refreshToken() const;
  QString token() const;
  void setToken(QString token);
  void setRefreshToken(QString refreshToken);
  void setExpirationAt(QDateTime expirationAt);
};

#endif // AUTHORIZATIONDATA_HXX
