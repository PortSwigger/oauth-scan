OAUTHScan
===================

# Description
OAUTHScan is a Burp Suite Extension written in Java with the aim to provide some automatic security checks, which could be useful during penetration testing on applications implementing OAUTHv2 and OpenID standards.

The plugin looks for various OAUTHv2/OpenID vulnerabilities and common misconfigurations (based on official specifications of both frameworks), many of the checks have been developed according with the following references:

  * https://datatracker.ietf.org/doc/html/rfc6749
  * https://datatracker.ietf.org/doc/html/rfc6819
  * https://datatracker.ietf.org/doc/html/rfc6750
  * https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-09
  * https://oauth.net/2/
  * https://openid.net/connect/
  * https://openid.net/specs/openid-connect-core-1_0.html
  * https://portswigger.net/web-security/oauth
  * https://portswigger.net/web-security/oauth/openid


Below a non-exhaustive list of the checks performed by OAUTHScan:

  * Open Redirect issues on Redirect_Uri parameter
  * Authorization Code Replay issues
  * Leakage of secrets (i.e. Tokens, Codes)
  * PKCE misconfigurations
  * Nonce parameter misconfigurations
  * State parameter misconfiguration
  * Input Validation issues on Scope parameter
  * Detection of inerently insecure Flows
  * SSRF issues via Request_Uri parameter
  * Detection of Well-Known and WebFinger resources
  * And others...


# Installation
After downloaded (or cloned) the OAUTHScan repository, build it using gradle, and finally import the generated 'OAUTHscan-1.0.jar' file via Burp Extender tab. Alternatively is possible to install it from official Burp App Store.


# Usage
OAUTHScan is fully integrated with the Burp Scanner, after installed on Burp you have only to launch Passive or Active scans on your targeted request.


# Author
- OAUTHScan plugin was developed by Maurizio Siddu


# GNU License
Copyright (c) 2022 OAUTHScan

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>
