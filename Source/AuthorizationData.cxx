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
