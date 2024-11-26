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


Below a non-exhaustive list of checks performed by OAUTHScan:

  * Open Redirect issues on Redirect_Uri parameter
  * Authorization Code Replay issues
  * Leakage of secrets (i.e. Tokens, Codes, Client Secrets)
  * PKCE misconfigurations
  * Nonce parameter misconfigurations
  * State parameter misconfiguration
  * Input Validation issues on Scope parameter
  * Detection of inherently insecure Flows
  * SSRF issues via Request_Uri parameter
  * Detection of Well-Known and WebFinger resources
  * And others...


# Installation
First download/clone the OAUTHScan project from this Github repository.
Then you could build it:
* via CLI using gradle command: `gradlew build fatJar`;
* via GUI using the extension "Gradle for Java" for VS-Code: 
    Open open the OAUTHScan folder with VS-Code editor. Then select 
    the "elephant icon" of Gradle in the left vertical panel, so on 
    the "gradle projects" section click on "OauthScan" -> "Tasks" -> 
    "build". To build the project you have to click on the right arrow 
    of the "build" sub-option.

Finally use the Burp GUI Extender tab to import the generated 'OAUTHscan-X.Y.jar' file located on "build/libs/" project folder.
In alternative you could add OAUTHScan plugin directly from the official Burpsuite BApp-Store (Note: it could be not up-to-date).


# Usage
OAUTHScan is fully integrated with the Burp Scanner, after installed on Burp you have only to launch Passive or Active scans on your targeted request.

Alternatively it is also possible to run it as single-extension scan following these steps:
 * On Burp dashboard click the "New scan" button to open the "New Scan" configuration panel
 * Go into "Scan configuration" tab and click the button "Select from library"
 * Then choose the option "Audit checks - extensions only" and save
 * On Burp disable every other extension (if applicable) that performs active scan checks, so that only the OauthScan active scan runs
 * Right-click on the HTTP request to scan and select "Scan" option to open the submenu with the previously generated single-extension scan


# Note
The checks on this Burp plugin have been implemented following the RFCs of OAUTHv2 and OpenID. 
This could produce false positives when used to test applications having custom implementations of these standards.
The plugin on the original developer's Github repository may be more up-to-date than the one in Portswigger repository.


# Version
OAUTHScan current version is v1.2


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
