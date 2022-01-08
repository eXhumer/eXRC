#include "AuthorizationData.hxx"

AuthorizationData::AuthorizationData(QDateTime expirationAt, QString token,
                                     QString refreshToken, QObject *parent)
    : QObject(parent) {
  m_expirationAt = expirationAt;
  m_token = token;
  m_refreshToken = refreshToken;
}

AuthorizationData::AuthorizationData(QObject *parent)
    : AuthorizationData(QDateTime(), QString(), QString(), parent) {}

bool AuthorizationData::expired() const {
  return m_expirationAt.isValid() && !m_token.isEmpty()
             ? m_expirationAt <= QDateTime::currentDateTime()
             : true;
}

QDateTime AuthorizationData::expirationAt() const { return m_expirationAt; }

QString AuthorizationData::refreshToken() const { return m_refreshToken; }

QString AuthorizationData::token() const { return m_token; }

void AuthorizationData::setToken(QString token) { m_token = token; }

void AuthorizationData::setRefreshToken(QString refreshToken) {
  m_refreshToken = refreshToken;
}

void AuthorizationData::setExpirationAt(QDateTime expirationAt) {
  m_expirationAt = expirationAt;
}
