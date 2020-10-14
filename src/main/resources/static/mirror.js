"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
function reflect() {
    var urlHref = document.location.href;
    var title = document.title;
    var reflectedParams = findReflection();
    if (reflectedParams.length > 0) {
        var mirrorData = {
            url: urlHref,
            parameters: reflectedParams,
            title: title,
        };
        addToMirror(mirrorData);
    }
}
function findReflection() {
    var hashUrl = document.location.hash.replace("#", "");
    var searchUrl = document.location.search.replace("?", "");
    var hashParams = getParams(hashUrl);
    var searchParams = getParams(searchUrl);
    var rawParams = hashParams.concat(searchParams);
    var decodedParams = rawParams.map(function (param) { return decodeURIComponent(param); });
    var allParams = rawParams.concat(decodedParams);
    var uniqueParams = Array.from(new Set(allParams));
    var body = document.body.innerHTML;
    var reflectedParams = uniqueParams.filter(function (param) { return body.includes(param); });
    return reflectedParams;
}
function getParams(params) {
    var keyValues = params
        .split("&")
        .map(function (param) {
        var kv = param.split("=");
        if (kv.length == 2) {
            return kv[1];
        }
        else {
            return kv[0];
        }
    })
        .filter(function (param) { return param.length > 3; });
    return keyValues;
}
function addToMirror(mirroData) {
    return __awaiter(this, void 0, void 0, function () {
        return __generator(this, function (_a) {
            fetch("http://localhost:3033/mirror/add", {
                method: "POST",
                mode: "cors",
                credentials: "omit",
                body: JSON.stringify(mirroData),
                headers: {
                    "Content-Type": "application/json",
                },
            });
            return [2 /*return*/];
        });
    });
}
reflect();
