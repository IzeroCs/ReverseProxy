const jwt        = require("jsonwebtoken")
const fs         = require("fs")
const axios      = require("axios")
const crypto     = require("crypto-js")
const express    = require("express")
const validateIP = require("validate-ip-node")
const ippub      = require("ipify2")
const https      = require("https")

const { AbortController } = require("axios")

if (process.env.NODE_ENV == "production")
    require("dotenv").config({ path: ".env" })
else
    require("dotenv").config({ path: ".env.development"})

const NODE_PRODUCTION      = process.env.NODE_ENV == "production"
const PRIVATE_KEY_JWT      = process.env.PATH_JWT_PRIVATE_KEY  || "./private.key"
const SECRET_KEY_AES       = process.env.PATH_AES_SECRET_KEY   || "./secret.key"
const IP_UPDATE_FILE       = process.env.PATH_IP_UPDATE_CLIENT || "./ip.client"
const ROUTER_TOKEN_PORT    = process.env.ROUTER_TOKEN_PORT     || 9912

if (!process.env.DOMAIN_ROUTER_UPDATE)
    throw Error("Not found env DOMAIN_ROUTER_UPDATE, put to env")

const TIME_CLIENT_CANCEL_REQUEST    = process.env.TIME_CLIENT_CANCEL_REQUEST    || 5000
const TIME_CLIENT_INTERVAL_REQUEST  = process.env.TIME_CLIENT_INTERVAL_REQUEST  || 10000
const TIME_CLIENT_RESOLVE_PUBLIC_IP = process.env.TIME_CLIENT_RESOLVE_PUBLIC_IP || 10000
const TIME_CLIENT_BETWEEN_REQUEST   = process.env.TIME_CLIENT_BETWEEN_REQUEST   || 10000
const URL_ROUTER_UPDATE_IP          = (() => {
    let domain = process.env.DOMAIN_ROUTER_UPDATE

    if (!domain.startsWith("http"))
        domain = "http://" + domain

    return domain + (process.env.ROUTER_UPDATE_PATH || "/update")
})()

if (!fs.existsSync(PRIVATE_KEY_JWT))
    throw Error("Public key for JsonWebToken not found, generator and put to folder")

if (!fs.existsSync(SECRET_KEY_AES))
    throw Error("Secret key for Crypto AES not found, generator and put to folder")

const privkey = fs.readFileSync(PRIVATE_KEY_JWT, "utf-8")
const secret  = fs.readFileSync(SECRET_KEY_AES, "utf-8")
const app     = express()

const crypto_message = process.env.CRYPTO_MESSAGE || "IzeroCs"

let axios_source = null
let ip_update    = null
let busy_update  = false
let busy_time    = Date.now()
let token        = ""

if (fs.existsSync(IP_UPDATE_FILE)) {
    const ip = fs.readFileSync(IP_UPDATE_FILE, "utf-8")

    if (validateIP(ip))
        ip_update = ip
}

function sign() {
    return jwt.sign({
        ip: ip_update,
        uid: 3984595837
    }, privkey, {
        issuer: "IzeroCs",
        subject: "izero.cs@gmail.com",
        algorithm: "RS512",
        expiresIn: "10s"
    })
}

app.use(express.json())

if (!NODE_PRODUCTION)
    app.get("/", (req, res) => res.send("Router client update IP..."))

app.post(process.env.ROUTER_TOKEN_PATH || "/token", (req, res) => {
    res.send(token)
})

app.listen(ROUTER_TOKEN_PORT, () => console
    .log("Router token listen on port " + ROUTER_TOKEN_PORT))

setInterval(() => {
    if (!busy_update) {
        busy_update  = true
        busy_time    = Date.now()
        axios_source = axios.CancelToken.source()
        token        = sign()

        axios({
            method: "POST",
            url: URL_ROUTER_UPDATE_IP,
            cancelToken: axios_source.token,
            httpsAgent: (() => {
                if (URL_ROUTER_UPDATE_IP.startsWith("https")) {
                    return new https.Agent({
                        rejectUnauthorized: false
                    })
                }

                return new https.Agent({ keepAlive: true })
            })(),
            data: {
                token: token,
                rsi: crypto.AES.encrypt(crypto_message,
                        secret).toString()
            }
        }).then(res => {
            busy_update  = true
            busy_time    = Date.now()
            axios_source = null
            token        = ""

            if (res.data == "UPDATED" || res.data == "NOTUPDATE") {
                if (res.data == "UPDATED")
                    console.log("Updated Router IP")
            } else {
                console.log("Error: Update Error")
            }
        }).catch(err => {
            busy_update  = true
            busy_time    = Date.now()
            axios_source = null
            token        = ""

            if (err.response) {
                const statusCode = err.response.status
                const statusText = err.response.statusText

                console.log("Error: Request " + statusCode + " " + statusText)
            } else {
                console.log("Error:", err.message || "Unknow Error")
            }
        })
    } else {
        if (axios_source) {
            if (Date.now() - busy_time > TIME_CLIENT_CANCEL_REQUEST) {
                busy_update = false
                busy_time   = 0

                axios_source.cancel("Cancel Request")
            }
        } else if (Date.now() - busy_time > TIME_CLIENT_BETWEEN_REQUEST) {
            busy_update = false
            busy_time   = 0
        }
    }
}, TIME_CLIENT_INTERVAL_REQUEST)

setInterval(() => {
    ippub.ipv4().then(ip => {
        if (validateIP(ip)) {
            ip_update = ip
            fs.writeFileSync(IP_UPDATE_FILE, ip)
        }
    }).catch(err => console.log("Error: Resolve IP Failed"))
}, TIME_CLIENT_RESOLVE_PUBLIC_IP)
