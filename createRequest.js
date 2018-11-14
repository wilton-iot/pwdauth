/*
 * Copyright 2018, alex at staticlibs.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

define([
    "lodash/isEmpty",
    "lodash/isString",
    "./hmac_sha256",
    "./sha256"
], function(isEmpty, isString, hmac, hash) {
    "use strict";

    var label = "PWDAUTH";

    function signature(path, pwdHash, timestamp) {
        var kDate = hmac(label + pwdHash, timestamp);
        var kCredentials = hmac(kDate, label.toLowerCase() + "_request");
        return hmac(kCredentials, stringToSign(path, timestamp));
    }

    function stringToSign(path, timestamp) {
        return [
          label+ "-HMAC-SHA256",
          timestamp,
          hash(path)
        ].join("\n");
    }
    
    function canonicalString(path) {
        if (path !== "/") {
          path = path.replace(/\/{2,}/g, "/");
          path = path.split("/").reduce(function(path, piece) {
            if (piece === "..") {
              path.pop();
            } else if (piece !== ".") {
              path.push(encodeRfc3986(encodeURIComponent(piece)));
            }
            return path;
          }, []).join("/");
          if (path[0] !== "/") path = "/" + path;
        }
        return path;
    }

    function encodeRfc3986(urlEncodedString) {
        return urlEncodedString.replace(/[!'()*]/g, function(c) {
          return "%" + c.charCodeAt(0).toString(16).toUpperCase();
        });
    }

    return function(path, userId, pwdHash, timestamp) {
        if (!isString(path) || isEmpty(path)) {
            throw new Error("Invalid 'path' parameter specified");
        }
        if (!isString(userId) || isEmpty(userId)) {
            throw new Error("Invalid 'userId' parameter specified");
        }
        if (!isString(pwdHash) || isEmpty(pwdHash)) {
            throw new Error("Invalid 'pwdHash' parameter specified");
        }
        if (!isString(timestamp) || isEmpty(timestamp)) {
            throw new Error("Invalid 'timestamp' parameter specified");
        }

        var canonicalPath = canonicalString(path);

        return {
            key: userId,
            hmac: signature(canonicalPath, pwdHash, timestamp),
            timestamp: timestamp,
            path: canonicalPath
        };
    };
});
