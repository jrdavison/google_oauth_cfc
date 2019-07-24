# ColdFusion Google OAuth2 Component

ColdFusion component to get an OAuth2 token for a Google Service Account to access certain google APIs

## Usage

### Installation

Create a Google service account. Instructions on how to create this account can be found here [here](https://developers.google.com/identity/protocols/OAuth2ServiceAccount).

Creating a service account will provide you with an option to download a JSON file containing relevant information (such as the private key). Set `<!--- PATH TO KEY FILE --->` on line 21 to the absolute file path of the key.json file.

Usable with any Google API that uses OAuth2 authentication (e.g. The Google Analytics API). This authentication token will be sent in the header of all HTTP requests to a given API endpoint.
 
### Reference
- [JSON Web Tokens](https://tools.ietf.org/html/rfc7515)
- [More Information on Encryption in ColdFusion](https://www.bennadel.com/blog/2941-experimenting-with-rsa-encrypted-signature-generation-and-verification-in-coldfusion.htm)
