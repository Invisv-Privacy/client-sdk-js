import E2EEManager from './e2ee';
import log from '../logger';

const manager = new E2EEManager();

const handleTransform = ({
  operation,
  readable,
  writable,
}: {
  operation: string;
  readable: any;
  writable: any;
}) => {
  if (operation === 'encode') {
    const transformer = new TransformStream({
      transform: manager.encodeFunction.bind(manager),
    });
    readable.pipeThrough(transformer).pipeTo(writable);
  } else if (operation === 'decode') {
    const transformer = new TransformStream({
      transform: manager.decodeFunction.bind(manager),
    });
    readable.pipeThrough(transformer).pipeTo(writable);
  }
};
onmessage = async (event) => {
  const { operation, readable, writable } = event.data;
  log.trace('message received', { event });

  if (operation === 'setPassword') {
    const { password } = event.data;
    await manager.setPassword(password);
  } else if (operation === 'rotateKey') {
    await manager.rotateKey();
  } else {
    handleTransform({ operation, readable, writable });
  }
};

// Operations using RTCRtpScriptTransform.
// @ts-expect-error
if (self.RTCTransformEvent) {
  // @ts-expect-error
  self.onrtctransform = (event: any) => {
    const { transformer } = event;
    const {
      readable,
      writable,
      options: { operation },
    } = transformer;

    handleTransform({ operation, readable, writable });
  };
}
export {};
