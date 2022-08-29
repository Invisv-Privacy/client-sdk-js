
let currentCryptoKey = "123456789";
let useCryptoOffset = true;
let currentKeyIdentifier = 0;

const frameTypeToCryptoOffset = {
	key: 10,
	delta: 3, 
	undefined: 1,
}

function dump(encodedFrame, direction, max = 16) {
  const data = new Uint8Array(encodedFrame.data);
  let bytes = '';
  for (let j = 0; j < data.length && j < max; j++) {
    bytes += (data[j] < 16 ? '0' : '') + data[j].toString(16) + ' ';
  }
  console.log(performance.now().toFixed(2), direction, bytes.trim(),
      'len=' + encodedFrame.data.byteLength,
      'type=' + (encodedFrame.type || 'audio'),
      'ts=' + encodedFrame.timestamp,
      'ssrc=' + encodedFrame.getMetadata().synchronizationSource,
      'pt=' + (encodedFrame.getMetadata().payloadType || '(unknown)')
  );
}

let scount = 0;
export function encodeFunction(encodedFrame, controller) {
	if (scount++ < 30) {
		dump(encodedFrame, 'send');
	}
	if (currentCryptoKey) {
		const view = new DataView(encodedFrame.data);
		// Any length that is needed can be used for the new buffer.
		const newData = new ArrayBuffer(encodedFrame.data.byteLength + 5);
		const newView = new DataView(newData);

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

let rcount = 0;
export function decodeFunction(encodedFrame : any, controller : any) {
	if (rcount++ < 30) {
		dump(encodedFrame, "recv");
	}
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


