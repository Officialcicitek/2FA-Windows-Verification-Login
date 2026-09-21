const express = require("express");
const https = require("https");
const fs = require("fs");
const WebSocket = require("ws");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");

const app = express();


// ============================================================
// HTTPS SERVER
// ============================================================

const server = https.createServer(
    {
        pfx: fs.readFileSync(
            path.join(
                __dirname,
                "cert",
                "phoneunlock.pfx"
            )
        ),

        passphrase: "PhoneUnlock123!"
    },

    app
);


app.use(cors());
app.use(express.json());


// ============================================================
// WEBSOCKET
// ============================================================

const wss =
    new WebSocket.Server({
        server
    });


// ============================================================
// STORAGE
// ============================================================

const loginRequests = new Map();
const pairingCodes = new Map();
const pairedDevices = new Map();


// ============================================================
// SECURITY HELPERS
// ============================================================

function secretsMatch(secretA, secretB) {

    if (
        typeof secretA !== "string" ||
        typeof secretB !== "string"
    ) {
        return false;
    }

    const bufferA =
        Buffer.from(
            secretA,
            "utf8"
        );

    const bufferB =
        Buffer.from(
            secretB,
            "utf8"
        );

    if (
        bufferA.length !==
        bufferB.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        bufferA,
        bufferB
    );
}


function getPairSecret(req) {

    const authorization =
        req.headers.authorization;

    if (!authorization) {
        return null;
    }

    if (
        !authorization.startsWith(
            "Bearer "
        )
    ) {
        return null;
    }

    return authorization.substring(7);
}


function createApprovalProof(
    pairSecret,
    requestId,
    challenge
) {

    return crypto
        .createHmac(
            "sha256",
            pairSecret
        )
        .update(
            requestId +
            ":" +
            challenge,
            "utf8"
        )
        .digest("hex");
}


function verifyApprovalProof(
    pairSecret,
    requestId,
    challenge,
    proof
) {

    if (
        typeof proof !== "string" ||
        !/^[0-9a-f]{64}$/i.test(
            proof
        )
    ) {
        return false;
    }

    const expectedProof =
        createApprovalProof(
            pairSecret,
            requestId,
            challenge
        );

    const proofBuffer =
        Buffer.from(
            proof,
            "hex"
        );

    const expectedBuffer =
        Buffer.from(
            expectedProof,
            "hex"
        );

    if (
        proofBuffer.length !==
        expectedBuffer.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        proofBuffer,
        expectedBuffer
    );
}


// ============================================================
// WEBSOCKET HELPERS
// ============================================================

function sendToPair(
    pairId,
    data
) {

    const message =
        JSON.stringify(data);

    wss.clients.forEach(
        (client) => {

            if (
                client.readyState ===
                    WebSocket.OPEN &&
                client.pairId ===
                    pairId
            ) {

                client.send(
                    message
                );
            }
        }
    );
}


// ============================================================
// WEB PAGES
// ============================================================

app.get(
    "/",
    (req, res) => {

        res.json({
            name:
                "PhoneUnlock Server",

            status:
                "online",

            protocol:
                "https"
        });
    }
);


app.get(
    "/mobile",
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "mobile.html"
            )
        );
    }
);


app.get(
    "/pair",
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "pair.html"
            )
        );
    }
);


// ============================================================
// PAIRING
// ============================================================

app.post(
    "/pairing/create",
    (req, res) => {

        const {
            deviceName
        } = req.body;

        if (!deviceName) {

            return res
                .status(400)
                .json({
                    error:
                        "deviceName is required"
                });
        }

        const code =
            crypto
                .randomInt(
                    100000,
                    1000000
                )
                .toString();

        pairingCodes.set(
            code,
            {
                deviceName,

                createdAt:
                    Date.now()
            }
        );

        console.log(
            `🔗 Pairing code created for ${deviceName}: ${code}`
        );

        res.json({
            code,

            deviceName
        });
    }
);


app.post(
    "/pairing/confirm",
    (req, res) => {

        const {
            code,
            phoneName
        } = req.body;

        if (
            !code ||
            !phoneName
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "code and phoneName are required"
                });
        }

        const pairing =
            pairingCodes.get(
                code
            );

        if (!pairing) {

            return res
                .status(404)
                .json({
                    error:
                        "Invalid or expired pairing code"
                });
        }

        if (
            Date.now() -
            pairing.createdAt >
            5 * 60 * 1000
        ) {

            pairingCodes.delete(
                code
            );

            return res
                .status(400)
                .json({
                    error:
                        "Pairing code expired"
                });
        }

        const pairId =
            crypto
                .randomBytes(16)
                .toString("hex")
                .toUpperCase();

        const pairSecret =
            crypto
                .randomBytes(32)
                .toString("hex");

        const pair = {

            pairId,

            pairSecret,

            deviceName:
                pairing.deviceName,

            phoneName,

            createdAt:
                Date.now()
        };

        pairedDevices.set(
            pairId,
            pair
        );

        pairingCodes.delete(
            code
        );

        console.log(
            `🔗 Paired: ${pair.deviceName} ↔ ${pair.phoneName}`
        );

        console.log(
            `🔑 Secure pair created: ${pairId}`
        );

        res.json({
            success:
                true,

            pair
        });
    }
);


app.get(
    "/pairing/device/:deviceName",
    (req, res) => {

        const deviceName =
            req.params.deviceName;

        const pair =
            [
                ...pairedDevices.values()
            ].find(
                item =>
                    item.deviceName ===
                    deviceName
            );

        if (!pair) {

            return res
                .status(404)
                .json({
                    error:
                        "Device is not paired"
                });
        }

        res.json({

            pairId:
                pair.pairId,

            pairSecret:
                pair.pairSecret,

            deviceName:
                pair.deviceName,

            phoneName:
                pair.phoneName
        });
    }
);


// ============================================================
// LOGIN REQUEST
// ============================================================

app.post(
    "/auth/request",
    (req, res) => {

        const {
            deviceName,
            pairId,
            pairSecret,
            challenge
        } = req.body;


        if (!deviceName) {

            return res
                .status(400)
                .json({
                    error:
                        "deviceName is required"
                });
        }


        if (!pairId) {

            return res
                .status(400)
                .json({
                    error:
                        "pairId is required"
                });
        }


        if (!pairSecret) {

            return res
                .status(400)
                .json({
                    error:
                        "pairSecret is required"
                });
        }


        if (
            typeof challenge !==
                "string" ||

            challenge.length < 32 ||

            challenge.length > 128 ||

            !/^[0-9a-f]+$/i.test(
                challenge
            )
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Valid challenge is required"
                });
        }


        const pair =
            pairedDevices.get(
                pairId
            );


        if (!pair) {

            return res
                .status(403)
                .json({
                    error:
                        "Device is not paired"
                });
        }


        if (
            pair.deviceName !==
            deviceName
        ) {

            return res
                .status(403)
                .json({
                    error:
                        "Device name does not match pairing"
                });
        }


        if (
            !secretsMatch(
                pair.pairSecret,
                pairSecret
            )
        ) {

            return res
                .status(403)
                .json({
                    error:
                        "Invalid pair secret"
                });
        }


        const requestId =
            crypto
                .randomBytes(8)
                .toString("hex")
                .toUpperCase();


        const now =
            Date.now();


        const request = {

            requestId,

            deviceName,

            pairId,

            challenge,

            status:
                "pending",

            createdAt:
                now,

            expiresAt:
                now +
                60 * 1000
        };


        loginRequests.set(
            requestId,
            request
        );


        // ========================================================
        // AUTOMATIC EXPIRATION
        // ========================================================

        setTimeout(
            () => {

                const currentRequest =
                    loginRequests.get(
                        requestId
                    );


                if (
                    !currentRequest ||
                    currentRequest.status !==
                        "pending"
                ) {
                    return;
                }


                currentRequest.status =
                    "expired";


                currentRequest.expiredAt =
                    Date.now();


                console.log(
                    `⏱️ Login request expired: ${requestId}`
                );


                sendToPair(
                    currentRequest.pairId,
                    {
                        type:
                            "login_expired",

                        request:
                            currentRequest
                    }
                );

            },

            60 * 1000
        );


        // ========================================================
        // CLEANUP
        // ========================================================

        setTimeout(
            () => {

                const currentRequest =
                    loginRequests.get(
                        requestId
                    );


                if (!currentRequest) {
                    return;
                }


                loginRequests.delete(
                    requestId
                );


                console.log(
                    `🧹 Login request removed: ${requestId}`
                );

            },

            5 * 60 * 1000
        );


        console.log(
            `🔐 Login request: ${requestId} from ${deviceName}`
        );


        // ========================================================
        // SEND TO CONNECTED PHONE
        // ========================================================

        sendToPair(
            request.pairId,
            {
                type:
                    "login_request",

                request
            }
        );


        res.json(
            request
        );
    }
);


// ============================================================
// AUTHENTICATION
// ============================================================

function authenticateRequest(
    req,
    request
) {

    const pair =
        pairedDevices.get(
            request.pairId
        );


    if (!pair) {

        return {

            ok:
                false,

            status:
                403,

            error:
                "Device is not paired"
        };
    }


    const pairSecret =
        getPairSecret(
            req
        );


    if (!pairSecret) {

        return {

            ok:
                false,

            status:
                401,

            error:
                "pairSecret is required"
        };
    }


    if (
        !secretsMatch(
            pair.pairSecret,
            pairSecret
        )
    ) {

        return {

            ok:
                false,

            status:
                403,

            error:
                "Invalid pair secret"
        };
    }


    return {

        ok:
            true,

        pair
    };
}


// ============================================================
// GET REQUEST STATUS
// ============================================================

app.get(
    "/auth/request/:id",
    (req, res) => {

        const request =
            loginRequests.get(
                req.params.id
            );


        if (!request) {

            return res
                .status(404)
                .json({
                    error:
                        "Request not found"
                });
        }


        const authentication =
            authenticateRequest(
                req,
                request
            );


        if (
            !authentication.ok
        ) {

            return res
                .status(
                    authentication.status
                )
                .json({
                    error:
                        authentication.error
                });
        }


        res.json(
            request
        );
    }
);


// ============================================================
// APPROVE
// ============================================================

app.post(
    "/auth/request/:id/approve",
    (req, res) => {

        const request =
            loginRequests.get(
                req.params.id
            );


        if (!request) {

            return res
                .status(404)
                .json({
                    error:
                        "Request not found"
                });
        }


        const authentication =
            authenticateRequest(
                req,
                request
            );


        if (
            !authentication.ok
        ) {

            return res
                .status(
                    authentication.status
                )
                .json({
                    error:
                        authentication.error
                });
        }


        const pair =
            authentication.pair;


        if (
            request.status !==
            "pending"
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Request is no longer pending"
                });
        }


        if (
            Date.now() >=
            request.expiresAt
        ) {

            request.status =
                "expired";


            request.expiredAt =
                Date.now();


            console.log(
                `⏱️ Login request expired: ${request.requestId}`
            );


            sendToPair(
                request.pairId,
                {
                    type:
                        "login_expired",

                    request
                }
            );


            return res
                .status(400)
                .json({
                    error:
                        "Request expired"
                });
        }


        const {
            proof
        } = req.body;


        const validProof =
            verifyApprovalProof(
                pair.pairSecret,
                request.requestId,
                request.challenge,
                proof
            );


        if (!validProof) {

            console.log(
                `⚠️ Invalid approval proof: ${request.requestId}`
            );


            return res
                .status(403)
                .json({
                    error:
                        "Invalid approval proof"
                });
        }


        request.status =
            "approved";


        request.approvedAt =
            Date.now();


        request.approvalProof =
            proof;


        console.log(
            `✅ Login cryptographically approved: ${request.requestId}`
        );


        sendToPair(
            request.pairId,
            {
                type:
                    "login_approved",

                request
            }
        );


        res.json(
            request
        );
    }
);


// ============================================================
// DENY
// ============================================================

app.post(
    "/auth/request/:id/deny",
    (req, res) => {

        const request =
            loginRequests.get(
                req.params.id
            );


        if (!request) {

            return res
                .status(404)
                .json({
                    error:
                        "Request not found"
                });
        }


        const authentication =
            authenticateRequest(
                req,
                request
            );


        if (
            !authentication.ok
        ) {

            return res
                .status(
                    authentication.status
                )
                .json({
                    error:
                        authentication.error
                });
        }


        if (
            request.status !==
            "pending"
        ) {

            return res
                .status(400)
                .json({
                    error:
                        "Request is no longer pending"
                });
        }


        if (
            Date.now() >=
            request.expiresAt
        ) {

            request.status =
                "expired";


            request.expiredAt =
                Date.now();


            console.log(
                `⏱️ Login request expired: ${request.requestId}`
            );


            sendToPair(
                request.pairId,
                {
                    type:
                        "login_expired",

                    request
                }
            );


            return res
                .status(400)
                .json({
                    error:
                        "Request expired"
                });
        }


        request.status =
            "denied";


        request.deniedAt =
            Date.now();


        console.log(
            `❌ Login denied: ${request.requestId}`
        );


        sendToPair(
            request.pairId,
            {
                type:
                    "login_denied",

                request
            }
        );


        res.json(
            request
        );
    }
);


// ============================================================
// WEBSOCKET CONNECTION
// ============================================================

wss.on(
    "connection",
    (socket) => {

        console.log(
            "📱 WebSocket client connected"
        );


        socket.pairId =
            null;


        socket.send(
            JSON.stringify({
                type:
                    "connected"
            })
        );


        socket.on(
            "message",
            (message) => {

                try {

                    const data =
                        JSON.parse(
                            message
                        );


                    // ====================================================
                    // PHONE REGISTRATION
                    // ====================================================

                    if (
                        data.type ===
                        "register_phone"
                    ) {

                        const pairId =
                            data.pairId;


                        const pairSecret =
                            data.pairSecret;


                        if (!pairId) {

                            socket.send(
                                JSON.stringify({
                                    type:
                                        "registration_failed",

                                    error:
                                        "pairId is required"
                                })
                            );

                            return;
                        }


                        if (!pairSecret) {

                            socket.send(
                                JSON.stringify({
                                    type:
                                        "registration_failed",

                                    error:
                                        "pairSecret is required"
                                })
                            );

                            return;
                        }


                        const pair =
                            pairedDevices.get(
                                pairId
                            );
                        
                            

                        if (!pair) {

                            console.log(
                                `⚠️ Invalid pairId attempted: ${pairId}`
                            );


                            socket.send(
                                JSON.stringify({
                                    type:
                                        "registration_failed",

                                    error:
                                        "Invalid pairId"
                                })
                            );

                            return;
                        }


                        if (
                            !secretsMatch(
                                pair.pairSecret,
                                pairSecret
                            )
                        ) {

                            console.log(
                                `⚠️ Invalid pair secret attempted for pair: ${pairId}`
                            );


                            socket.send(
                                JSON.stringify({
                                    type:
                                        "registration_failed",

                                    error:
                                        "Invalid pair secret"
                                })
                            );

                            return;
                        }


                        socket.pairId =
                            pairId;


                        console.log(
                            `📱 Phone registered: ${pair.phoneName} ↔ ${pair.deviceName}`
                        );


                        socket.send(
                            JSON.stringify({
                                type:
                                    "registration_success",

                                pair: {

                                    pairId:
                                        pair.pairId,

                                    deviceName:
                                        pair.deviceName,

                                    phoneName:
                                        pair.phoneName
                                }
                            })
                        );


                        // ====================================================
                        // DELIVER PENDING REQUEST AFTER RECONNECT
                        // ====================================================

                        for (
                            const request
                            of loginRequests.values()
                        ) {

                            if (
                                request.pairId ===
                                    pairId &&

                                request.status ===
                                    "pending" &&

                                Date.now() <
                                    request.expiresAt
                            ) {

                                socket.send(
                                    JSON.stringify({
                                        type:
                                            "login_request",

                                        request
                                    })
                                );


                                console.log(
                                    `📨 Pending login request delivered: ${request.requestId}`
                                );
                            }
                        }
                    }
                }

                catch (error) {

                    console.log(
                        "⚠️ Invalid WebSocket message"
                    );
                }
            }
        );


        socket.on(
            "close",
            () => {

                console.log(
                    "📱 WebSocket client disconnected"
                );
            }
        );
    }
);


// ============================================================
// SERVER
// ============================================================

const PORT = 3000;


server.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `🚀 PhoneUnlock HTTPS server running on https://0.0.0.0:${PORT}`
        );

        console.log(
            `📱 Mobile: https://10.0.32.162:${PORT}/mobile`
        );

        console.log(
            `🔗 Pairing: https://10.0.32.162:${PORT}/pair`
        );
    }
);