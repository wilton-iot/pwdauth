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
    "sjcl",
    "utf8"
], function(sjcl, utf8) {
    "use strict";

    function defaultString(str) {
        if ("string" === typeof (str)) {
            return str;
        } else if (!undefinedOrNull(str)) {
            return String(str);
        } else {
            return "";
        }
    }

// https://github.com/bitwiseshiftleft/sjcl/issues/225
//
// python -c "import hashlib;print hashlib.sha256('foo').hexdigest()"
// 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
// 
// python -c "import hashlib;print hashlib.sha256(u'привет'.encode('utf-8')).hexdigest()"
// 982c11281206e7b972ee4a5fcc85f362acf826314862212213de925079dc5652
// 
// python -c "import hashlib;print hashlib.sha256('').hexdigest()"
// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
// 
    return function(data) {
        var str = defaultString(data);
        var bytes = utf8.encode(str);
        var bits = sjcl.hash.sha256.hash(bytes);
        return sjcl.codec.hex.fromBits(bits);
    };

});
