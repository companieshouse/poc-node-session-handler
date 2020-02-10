"use strict";

const msgpack = require("msgpack");
const crypto = require("crypto");
const promisify = require("util").promisify;
const randomBytesAsync = promisify(crypto.randomBytes);

const createEncoder = function () {
    const me = {};

    me.decodeMsgpack = function (base) {
        return msgpack.unpack(base);
    };

    me.encodeMsgpack = function (base) {
        return msgpack.pack(base);
    };

    me.decodeBase64 = function (base) {
        return Buffer.from(base, "base64");
    };

    me.encodeBase64 = function (base) {
        return base.toString("base64");
    };

    me.generateSha1SumBase64 = function (base) {
        return crypto
            .createHash("sha1")
            .update(base)
            .digest("base64");
    };

    me.generateRandomBytesBase64 = async function (numBytes) {

        try {
            return await randomBytesAsync(numBytes).toString("base64");
        } catch (error) {
            return error;
        }
    };

    return me;
};

module.exports = createEncoder();