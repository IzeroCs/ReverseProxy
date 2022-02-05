const redbird    = require("redbird")
const express    = require("express")
const jwt        = require("jsonwebtoken")
const fs         = require("fs")
const crypto     = require("crypto-js")
const dotenv     = require("dotenv").config()
const validateIP = require("validate-ip-node")
const axios      = require("axios")
const path       = require("path")

const {
    TokenExpiredError,
    JsonWebTokenError
} = require("jsonwebtoken")
const { deepStrictEqual } = require("assert")

const REDBIRD_PORT       = 8080
const ROUTER_UPDATE_PORT = 9911
const ROUTER_TOKEN_PORT  = 9912
const PUBLIC_KEY_JWT     = "./public.key"
const SECRET_KEY_AES     = "./secret.key"
const IP_UPDATE_FILE     = "./ip.server"

const TIME_SERVER_RESOLVE_TOKEN_CLIENT = process.env.TIME_SERVER_RESOLVE_TOKEN_CLIENT || 10000
const TIME_SERVER_BETWEEN_UPDATE       = process.env.TIME_SERVER_BETWEEN_UPDATE       || 10000
const LETSENCRYPT_LIVE_PATH            = process.env.LETSENCRYPT_LIVE_PATH            || null
const LETSENCRYPT_PRIVKEY_NAME         = process.env.LETSENCRYPT_PRIVKEY_NAME         || "privkey.pem"
const LETSENCRYPT_CERT_NAME            = process.env.LETSENCRYPT_CERT_NAME            || "cert.pem"
const DOMAIN_ROUTER_UPDATE             = (() => {
    let domain = process.env.DOMAIN_ROUTER_UPDATE

    if (domain.startsWith("http"))
        domain = domain.substring(domain.indexOf("://") + 3)

    if (/\:[0-9]+\/?$/.test(domain))
        domain = domain.substring(0, domain.lastIndexOf(":"))

    return domain
})()

if (!fs.existsSync(PUBLIC_KEY_JWT))
    throw Error("Public key for JsonWebToken not found, generator new key and put to folder")

if (!fs.existsSync(SECRET_KEY_AES))
    throw Error("Secret key for Crypto AES not found, generator and put to folder")

if (!process.env.DOMAIN_ROUTER_UPDATE)
    throw Error("Not found env DOMAIN_ROUTER_UPDATE, put to env")

const app    = express()
const pubkey = fs.readFileSync(PUBLIC_KEY_JWT, "utf-8")
const secret = fs.readFileSync(SECRET_KEY_AES, "utf-8")
const proxy  = redbird({ port: REDBIRD_PORT, xfwd: false, ssl: { port: 443 } })

let crypto_message = process.env.CRYPTO_MESSAGE || "IzeroCs"
let ip_update      = ""
let time_update    = 0
let busy_update    = false

if (fs.existsSync(IP_UPDATE_FILE)) {
    let ip = fs.readFileSync(IP_UPDATE_FILE, "utf-8").trim()

    if (validateIP(ip))
        ip_update = ip
}

function set_ip_update(ip) {
    ip_update = ip
    fs.writeFileSync(IP_UPDATE_FILE, ip_update)
}

app.use(express.json())
app.post("/update", (req, res) => {
    if (!busy_update) {
        busy_update = true
        time_update = Date.now()

        if (!req.body.token || !req.body.rsi)
            return res.sendStatus(401)

        jwt.verify(req.body.token, pubkey, (err, decoded) => {
            if (err || !decoded || !decoded.ip)
                return res.sendStatus(401)

            try {
                const rsi = crypto.AES.decrypt(req.body.rsi, secret)

                if (rsi.toString(crypto.enc.Utf8) != crypto_message)
                    return res.sendStatus(401)
            } catch (e) {
                return res.sendStatus(401)
            }

            if (!validateIP(decoded.ip))
                return res.sendStatus(400)

            if (ip_update == decoded.ip)
                return res.send("NOTUPDATE")

            axios({
                method: "POST",
                url: "http://" + decoded.ip + ":" + ROUTER_TOKEN_PORT + "/token",
                timeout: TIME_SERVER_RESOLVE_TOKEN_CLIENT
            }).then(res_token => {
                if (res_token.data == req.body.token) {
                    busy_update = false
                    time_update = 0

                    set_ip_update(decoded.ip)
                    return res.send("UPDATED")
                } else {
                    return res.sendStatus(401)
                }
            }).catch (err => {
                return res.sendStatus(500)
            })
        })
    } else {
        return res.sendStatus(408)
    }
})

setInterval(() => {
    if (busy_update && Date.now() - time_update > TIME_SERVER_BETWEEN_UPDATE) {
        busy_update = false
        time_update = 0
    }
}, 1000)

app.listen(ROUTER_UPDATE_PORT, "127.0.0.1", () => {
    console.log("Router update IP run on 127.0.0.1:" + ROUTER_UPDATE_PORT)
})

const router_update_letsencrypt = path.join(LETSENCRYPT_LIVE_PATH, DOMAIN_ROUTER_UPDATE)
const router_update_key         = path.join(router_update_letsencrypt, LETSENCRYPT_PRIVKEY_NAME)
const router_update_cert        = path.join(router_update_letsencrypt, LETSENCRYPT_CERT_NAME)

if (!LETSENCRYPT_LIVE_PATH || !fs.existsSync(router_update_key) || !fs.existsSync(router_update_cert)) {
    proxy.register(DOMAIN_ROUTER_UPDATE, "127.0.0.1:" + ROUTER_UPDATE_PORT, { ssl: false })
} else {
    proxy.register(DOMAIN_ROUTER_UPDATE, "127.0.0.1:" + ROUTER_UPDATE_PORT, {
        ssl: {
            key: router_update_key,
            cert: router_update_cert
        }
    })
}
