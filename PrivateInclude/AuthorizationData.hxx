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

#ifndef AUTHORIZATIONDATA_HXX
#define AUTHORIZATIONDATA_HXX

#include <QDateTime>
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
