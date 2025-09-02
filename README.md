# Konfigurationsübung für die Keycloak-App von Univention

Dieses Repo enthält nur ein README.md mit Konfigurationsbefehlen zum Kopieren für die Keycloak-Schulung von Univention.

Aufgabe: In der Standard-Konfiguration der Trainingsumgebung ist das Univention Portal unter ``https://dn1.training.ucs`` und der Keycloak IdP unter ``https://ucs-sso-ng.training.ucs`` erreichbar.
Die aus dem Univention-Appcenter installierte Nextcloud-App (UCS 5.0) ist standardmäßig unter ``https://dn1.training.ucs/nextcloud`` zu finden.
Diese Konfiguration soll dahingehend verändert werden, dass

* das Univention-Portal jeder Schulungsinstanz von außen unter ``studentxx.univention.de`` erreichbar ist,
* die Keycloak-App jeder Schulungsinstanz von außen unter ``loginxx.univention.de`` erreichbar ist,
* beide Dienste mit TLS-Zertifikaten von Letsencrypt abgesichert sind,
* ein Login für das Portal und die Nextcloud-App über Keycloak (SAML 2.0) möglich ist.

## Definition der Domainnamen

Für die unten folgenden Befehle setzen Sie bitte eingangs einmalig die vollqualifizierten Domänennamen Ihrer Schulungsinstanz.
Fügen Sie statt `xx` die Nummer Ihrer Instanz ein.

```bash
PORTAL_FQDN="studentxx.univention.de"
SSO_FQDN="loginxx.univention.de"
NEXTCLOUD_FQDN="studentxx.univention.de"
```

## Letsencrypt-Zertifikat holen

```bash
# univention-app install letsencrypt # (hier vorinstalliert)
univention-app configure letsencrypt --set letsencrypt/domains="${PORTAL_FQDN} ${SSO_FQDN}" letsencrypt/services/apache2=True
systemctl restart apache2
```

## Änderung von Keycloaks Hostname

```bash
univention-app configure keycloak --set \
  keycloak/server/sso/fqdn="${SSO_FQDN}" \
  keycloak/server/sso/autoregistration=false \
  keycloak/apache2/ssl/certificate="/etc/univention/letsencrypt/signed_chain.crt" \
  keycloak/apache2/ssl/key="/etc/univention/letsencrypt/domain.key" \
  keycloak/csp/frame-ancestors="https://${PORTAL_FQDN} https://${SSO_FQDN}"
```

## Änderung des Portal-Hostname

Da das weiter unten aufzurufende Joinskript hardkodierte Pfade enthält, muss das Letsencrypt-Schlüsselmaterial unter den im UCS üblichen Pfaden verlinkt werden.
Es werden Symlinks statt Kopien verwendet, damit die Zertifikatserneuerung laufen kann.

```bash
mkdir /etc/univention/ssl/${PORTAL_FQDN}
ln -s /etc/univention/letsencrypt/signed_chain.crt /etc/univention/ssl/${PORTAL_FQDN}/cert.pem
ln -s /etc/univention/letsencrypt/domain.key /etc/univention/ssl/${PORTAL_FQDN}/private.key
```

Die SAML SP-Komponente des Portals wird umbenannt, damit das Portal von seiner neuen SAML EntityId weiß:

```bash
ucr set umc/saml/sp-server="${PORTAL_FQDN}"
```

Das Joinskript schreibt u.a. die SP-Metadaten der UMC neu nach `/usr/share/univention-management-console/saml/sp/metadata.xml`.
Die Datei wird nur mit `--force` geschrieben! Wenn man `--force` nutzt, sollte unbedingt ein konkretes Joinskript mit angegeben werden.

```bash
univention-run-join-scripts \
  --force \
  --run-scripts 92univention-management-console-web-server.inst
```

## Test der Webserver-Konfiguration

```bash
openssl s_client -connect ${PORTAL_FQDN}:443 | openssl x509 -noout -subject -issuer
openssl s_client -connect ${SSO_FQDN}:443 | openssl x509 -noout -subject -issuer
```

## Änderung des zuständigen IdP für die Anmeldung am Portal

```bash
ucr set umc/saml/idp-server="https://${SSO_FQDN}/realms/ucs/protocol/saml/descriptor"
```

## Aktivierung der SSO-Kachel im Portal

```bash
udm portals/entry modify --dn "cn=login-saml,cn=entry,cn=portals,cn=univention,$(ucr get ldap/base)" --set activated=TRUE
systemctl restart slapd
```

## Anpassung der Keycloak-Admin-Kachel

Die Schaltfläche im Portal, die zur Keycloak Admin Console führt, muss noch auf die neue URL umgestellt werden:

```bash
udm portals/entry modify --dn "cn=keycloak,cn=entry,cn=portals,cn=univention,dc=training,dc=ucs" --set link="en_US https://${SSO_FQDN}/admin/"
```

## Erzwingen von SAML SSO am Portal

Optional kann verhindert werden, dass Logins gegen OpenLDAP an Keycloak vorbei möglich sind:

```bash
ucr set umc/login/links/login_without_sso/enabled=false
ucr set portal/auth-mode=saml
```

## Umkonfiguration der Nextcloud als SAML-SP

* Der neue, von außen erreichbare FQDN muss in der Nextcloud-Konfiguration als vertrauenswürdig hinterlegt werden:

```bash
univention-app shell nextcloud sudo -u www-data php /var/www/html/occ config:system:set trusted_domains 2 --value ${NEXTCLOUD_FQDN}
```

* Das öffentliche Zertifikat für die SAML-Kommunikation aus Keycloak holen

```bash
univention-keycloak saml/idp/cert get --as-pem --output "/tmp/keycloak.cert"
```

* Die Keycloak-URL auslesen:

```bash
SSO_URL=`univention-keycloak get-keycloak-base-url`
```

* Änderung der Konfiguration der Nextcloud-Erweiterung "user_saml":

```bash
univention-app shell nextcloud sudo -u www-data /var/www/html/occ saml:config:set --idp-x509cert="$(cat /tmp/keycloak.cert)" --general-uid_mapping="uid" --idp-singleLogoutService.url="${SSO_URL}/realms/ucs/protocol/saml" --idp-singleSignOnService.url="${SSO_URL}/realms/ucs/protocol/saml" --idp-entityId="${SSO_URL}/realms/ucs" 1
```

* Prüfung:

```bash
univention-app shell nextcloud sudo -u www-data /var/www/html/occ saml:config:get
```

* Anlegen eines SAML-SP für Nextcloud in Keycloak
```bash
univention-keycloak saml/sp create --metadata-url="https://${NEXTCLOUD_FQDN}/nextcloud/apps/user_saml/saml/metadata" --role-mapping-single-value
```
