
let currentCryptoKey;
let useCryptoOffset = true;
let currentKeyIdentifier = 0;

const frameTypeToCryptoOffset = {
	key: 10,
	delta: 3, 
	undefined: 1,
}

function encodeFunction(encodedFrame, controller) {
	if (currentCryptoKey) {
		const view = new DataView(encodedFrame.data);

		const newData = new ArrayBuffer(encodedFrame.data.byteLength + 5);
		const newView = new DataView(newData)

		const cryptoOffset = useCryptoOffset? frameTypeToCryptoOffset[encodedFrame.type] : 0;

		for (let i = 0; i < cryptoOffset && i < encodedFrame.data.byteLength; ++i) {
			newView.setInt8(i, view.getInt8(i));
		}

		// Bitwise XOR of the key with the payload. NOT SECURE
		for (let i = cryptoOffset; i < encodedFrame.data.byteLength; ++i) {
			const keyByte = currentCryptoKey.charCodeAt(i % currentCryptoKey.length);
			newView.setInt8(i, view.getInt8(i) ^ keyByte);
		}
		// Append keyIdentifier.
		newView.setUint8(encodedFrame.data.byteLength, currentKeyIdentifier % 0xff);
		// Append checksum
		newView.setUint32(encodedFrame.data.byteLength + 1, 0xDEADBEEF); 

		encodedFrame.data = newData;
	}
	controller.enqueue(encodedFrame)
}

function decodeFunction(encodedFrame, controller) {
	const view = new DataView(encodedFrame.data);
	const checksum = encodedFrame.data.byteLength > 4 ? view.getUint32(encodedFrame.data.byteLength - 4) : false;
	if (currentCryptoKey) {
		if (checksum != 0xDEADBEEF) {
			console.log('Corrupted frame received, checksum ' + checksum.toString(16));
			return;
		}
		const keyIdentifier = view.getUint8(encodedFrame.data.byteLength - 5);
		if (keyIdentifier !== currentKeyIdentifier) {
			console.log(`Key identifier mismatch, got ${keyIdentifier} expected ${currentKeyIdentifier}.`);
			return;
		}

		const newData = new ArrayBuffer(encodedFrame.data.byteLength - 5);
		const newView = new DataView(newData);
		const cryptoOffset = useCryptoOffset? frameTypeToCryptoOffset[encodedFrame.type] : 0;

		for (let i = 0; i < cryptoOffset; ++i) {
			newView.setInt8(i, view.getInt8(i));
		}
		for (let i = cryptoOffset; i < encodedFrame.data.byteLength - 5; ++i) {
			const keyByte = currentCryptoKey.charCodeAt(i % currentCryptoKey.length);
			newView.setInt8(i, view.getInt8(i) ^ keyByte);
		}
		encodedFrame.data = newData;
	} else if (checksum == 0xDEADBEEF) {
		return;
	}
	controller.enqueue(encodedFrame);
}


