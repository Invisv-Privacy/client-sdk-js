import E2EEManager from './e2ee';
import log from '../logger';

const manager = new E2EEManager();

onmessage = async (event) => {
  const { operation, readable, writable } = event.data;
  log.trace('message received', { event });

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
  } else if (operation === 'setPassword') {
    const { password } = event.data;
    await manager.setKey(password);
  }
};

export {};
