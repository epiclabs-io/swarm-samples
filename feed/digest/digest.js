// Swarm Feeds JS digest and signature snippet
// Questions, comments, @jpeletier on ethersphere/orange-lounge gitter

// TODO: convert this snippet / integrate it into a proper library

let elliptic = require('elliptic');
let sha3 = require('js-sha3');
let ec = new elliptic.ec('secp256k1');

var topicLength = 32;
var userLength = 20;
var timeLength = 7;
var levelLength = 1;
var headerLength = 8;
var updateMinLength = topicLength + userLength + timeLength + levelLength + headerLength;

/* helper hex functions for data representation */

function hexToBytes(hex) {
	hex = hex.toString(16);

	hex = hex.replace(/^0x/i, '');

	for (var bytes = [], c = 0; c < hex.length; c += 2)
		bytes.push(parseInt(hex.substr(c, 2), 16));
	return bytes;
};

function bytesToHex(bytes, noprefix) {
	for (var hex = [], i = 0; i < bytes.length; i++) {
		hex.push((bytes[i] >>> 4).toString(16));
		hex.push((bytes[i] & 0xF).toString(16));
	}
	stHex = hex.join("");
	if (noprefix) {
		return stHex;
	}
	return "0x" + stHex;
};

function pubkeyToAddress(pubKey) {
	var pubBytes = pubKey.encode()
	return sha3.keccak256.array(pubBytes.slice(1)).slice(12);
}


// feedUpdateDigestData encodes a request object into a byte array so we can calculate
// a digest out of it.
function feedUpdateDigestData(request /*request*/, data /*UInt8Array*/) {
	var topicBytes = undefined;
	var userBytes = undefined;
	var protocolVersion = 0;

	protocolVersion = request.protocolVersion

	try {
		topicBytes = hexToBytes(request.feed.topic);
	} catch (err) {
		console.error("topicBytes: " + err);
		return undefined;
	}

	try {
		userBytes = hexToBytes(request.feed.user);
	} catch (err) {
		console.error("topicBytes: " + err);
		return undefined;
	}

	var buf = new ArrayBuffer(updateMinLength + data.length);
	var view = new DataView(buf);
	var cursor = 0;

	view.setUint8(cursor, protocolVersion) // first byte is protocol version.
	cursor += headerLength; // leave the next 7 bytes (padding) set to zero

	topicBytes.forEach(function (v) {
		view.setUint8(cursor, v);
		cursor++;
	});

	userBytes.forEach(function (v) {
		view.setUint8(cursor, v);
		cursor++;
	});

	// time is little-endian
	view.setUint32(cursor, request.epoch.time, true);
	cursor += 7;

	view.setUint8(cursor, request.epoch.level);
	cursor++;

	data.forEach(function (v) {
		view.setUint8(cursor, v);
		cursor++;
	});

	return new Uint8Array(buf);
}


// sign takes a private key and returns a byte array with the signature
function sign(digest, privateKey) {
	var sigRaw = ec.sign(digest, privateKey, { canonical: true });
	var signature = sigRaw.r.toArray();
	signature = signature.concat(sigRaw.s.toArray());
	signature.push(sigRaw.recoveryParam);
	return signature;
}

// example signature process

let keyPair = ec.keyFromPrivate("feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed");
let privKey = keyPair.getPrivate();

//print private key
console.log("Private Key: ", bytesToHex(privKey.toArray()));

// print address
addressBytes = pubkeyToAddress(keyPair.getPublic());
console.log("Address: ", bytesToHex(addressBytes));


// data payload to include in a feed update
data = new Uint8Array([0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x21]) // "hello world!!""

// request template, obtained calling http://localhost:8500/bzz-feed:/?user=<0xUSER>&topic=<0xTOPIC>&meta=1
request = {
	"feed": {
		"topic": "0x1234123412341234123412341234123412341234123412341234123412341234",
		"user": "0xafd79db96d018f333deb9ac821cc170f5cc81ea8" // must match the address coming out of the private key above!
	},
	"epoch": {
		"time": 1538650124,
		"level": 25
	},
	"protocolVersion": 0
}

// obtain digest data
digestData = feedUpdateDigestData(request, data);
console.log("Digest Data: ", bytesToHex(digestData));

// hash the digest data to obtain the digest
digest = sha3.keccak256.array(digestData);
console.log("Digest: ", bytesToHex(digest));

// Sign the digest with our private key
signature = sign(digest, privKey);
console.log("Signature: ", bytesToHex(signature));
