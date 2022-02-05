const jwt        = require("jsonwebtoken")
const fs         = require("fs")
const axios      = require("axios")
const crypto     = require("crypto-js")
const express    = require("express")
const dotenv     = require("dotenv").config()
const validateIP = require("validate-ip-node")
const ippub      = require("ipify2")

const { AbortController } = require("axios")

const PRIVATE_KEY_JWT      = "./private.key"
const SECRET_KEY_AES       = "./secret.key"
const IP_UPDATE_FILE       = "./ip.client"
const ROUTER_TOKEN_PORT    = 9912
const URL_ROUTER_UPDATE_IP = "http://192.168.31.114:8080/update"

const TIME_CLIENT_CANCEL_REQUEST    = process.env.TIME_CLIENT_CANCEL_REQUEST    || 5000
const TIME_CLIENT_INTERVAL_REQUEST  = process.env.TIME_CLIENT_INTERVAL_REQUEST  || 10000
const TIME_CLIENT_RESOLVE_PUBLIC_IP = process.env.TIME_CLIENT_RESOLVE_PUBLIC_IP || 10000
const TIME_CLIENT_BETWEEN_REQUEST   = process.env.TIME_CLIENT_BETWEEN_REQUEST   || 10000

if (!fs.existsSync(PRIVATE_KEY_JWT))
    throw Error("Public key for JsonWebToken not found, generator and put to folder")

if (!fs.existsSync(SECRET_KEY_AES))
    throw Error("Secret key for Crypto AES not found, generator and put to folder")

const privkey = fs.readFileSync(PRIVATE_KEY_JWT, "utf-8")
const secret  = fs.readFileSync(SECRET_KEY_AES, "utf-8")
const app     = express()

const crypto_message = process.env.CRYPTO_MESSAGE || "IzeroCs"

let axios_source = null
let ip_update    = "192.168.31.114"
let busy_update  = false
let busy_time    = Date.now()
let token        = ""

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
app.post("/token", (req, res) => {
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
        if (validateIP(ip))
            fs.writeFileSync(IP_UPDATE_FILE, ip)
    }).catch(err => console.log("Error: Resolve IP Failed"))
}, TIME_CLIENT_RESOLVE_PUBLIC_IP)
