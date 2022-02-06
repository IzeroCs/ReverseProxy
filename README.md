# This Reverse Proxy is used to update the dynamic public IP of the network router, no longer depending on Dynamic DNS.

**public.key, private.key:** Two files need to be created and in order to enter a directory, the path of the two files can be set in **.env**. Two files are used for **[JsonWebToken](https://www.npmjs.com/package/jsonwebtoken)**

**secret.key:** This file also needs to be created and in order to enter a directory, the path can be set in .env. File used for **[CryptoJS](https://www.npmjs.com/package/crypto-js)** to encrypt the authentication message to the server

**proxy.json** structure used for **[Redbird](https://www.npmjs.com/package/redbird)**, this file is created manually and is optional:
```
{
    "src": "target",

    "http://example.com":     "http://127.0.0.1:3000",
    "https://example.com":    "http://127.0.0.1:4000",
    "http://sub.example.com": "http://127.0.0.1:5000"
}
```

- **src:** If there is **https://** in the **src**, then automatically check in the Let's Encrypt folder set in **.env**. If there exist two files privkey.pem and cert.pem will enable ssl for that src-domain. If there is no scheme, the default will be **http://**

- **target:** With target, it can be internal IP or domain.

**ip.server, ip.client**: These two files are generated by the system when operating, it is used to save the router's public IP after authentication is complete, no pre-creation is required. Can set save path in **.env**
*********************************
## Environments:
| Key name                       | Description                                                                                           | Default               |
|--------------------------------|-------------------------------------------------------------------------------------------------------|---------------------- |
|CRYPTO_MESSAGE                  | Confirmation message with server                                                                      | Any string            |
|DOMAIN_ROUTER_UPDATE            | The domain name that handles the router's public IP update and confirmation                           | http://domain.com     |
|LETSENCRYPT_LIVE_PATH           | Let's Encrypt ssl key files storage path                                                              | /etc/letsencrypt/live |
|LETSENCRYPT_PRIVKEY_NAME        | The name of the ssl private key file stored in the Let's Encrypt folder                               | privkey.pem           |
|LETSENCRYPT_CERT_NAME           | The name of the ssl cert file stored in the Let's Encrypt folder                                      | cert.pem              |
|TIME_CLIENT_CANCEL_REQUEST      | The time that the client will drop the connection if there is no response from the server             | 5000                  |
|TIME_CLIENT_INTERVAL_REQUEST    | Test interval to create new request                                                                   | 60000                 |
|TIME_CLIENT_BETWEEN_REQUEST     | Time between two requests to the server                                                               | 60000                 |
|TIME_CLIENT_RESOLVE_PUBLIC_IP   | The time the client gets the router's new Public IP, if the router is restarted or the IP has changed | 60000                 |
|TIME_SERVER_RESOLVE_TOKEN_CLIENT| The time the server waits for the client to respond and return the token for authentication           | 10000                 |
|TIME_SERVER_BETWEEN_UPDATE      | The time between two times the server will receive a new request                                      | 60000                 |
|REDBIRD_PROXY_PORT              | Port for Redbird Proxy                                                                                | 80                    |
|ROUTER_UPDATE_PORT              | Internal port for receiving requests from the proxy domain                                            | 9911                  |
|ROUTER_TOKEN_PORT               | Port initiated by the client with a Public IP for the server to check the token                       | 9912                  |
|ROUTER_UPDATE_PATH              | The path of the url server update , domain.com/path-update                                            | /update               |
|ROUTER_TOKEN_PATH               | The path of the url client returns the token, IP Public: 1.2.3.4/path-token                           | /token                |
|PATH_JWT_PUBLIC_KEY             | The path of the public key file used for JsonWebToken                                                 | ./public.key          |
|PATH_JWT_PRIVATE_KEY            | The path of the private key file used for JsonWebToken                                                | ./private.key         |
|PATH_AES_SECRET_KEY             | The path of the secret key file used for CryptonJS                                                    | ./secret.key          |
|PATH_IP_UPDATE_SERVER           | The path to host IP Public client submits                                                             | ./ip.client           |
|PATH_IP_UPDATE_CLIENT           | Public IP storage path retrieved from **[ipify](https://www.ipify.org/)**                             | ./ip.server           |
|PATH_PROXY_REGISTER             | Reverse proxy registration list file path                                                             | ./proxy.jon           |

### For env **DOMAIN ROUTER UPDATE**, if it contains **https://** scheme, the system will check if there is ssl key and ssl cert of the domain in the Let's Encrypt path.
