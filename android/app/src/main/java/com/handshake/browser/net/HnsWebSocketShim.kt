package com.handshake.browser.net

import com.handshake.browser.core.IcannTlds

internal object HnsWebSocketShim {
    const val JS_OBJECT_NAME = "hnsWebSocketBridge"

    fun script(): String {
        val icannTlds = IcannTlds.ALL
            .sorted()
            .joinToString(",") { "'$it'" }
        return """
(function() {
  if (window.__hnsWebSocketShimInstalled) return;
  window.__hnsWebSocketShimInstalled = true;

  var NativeWebSocket = window.WebSocket;
  var bridge = window.$JS_OBJECT_NAME;
  if (!NativeWebSocket || !bridge || typeof bridge.postMessage !== 'function') return;

  var CONNECTING = 0;
  var OPEN = 1;
  var CLOSING = 2;
  var CLOSED = 3;
  var sockets = Object.create(null);
  var pageId = String(Date.now()) + '-' + String(Math.random()).slice(2);
  var nextId = 1;
  var icannTlds = new Set([$icannTlds]);
  var reservedSingleLabels = new Set(['example', 'invalid', 'local', 'localhost', 'test']);

  function normalizeHost(host) {
    return String(host || '').replace(/^\[/, '').replace(/\]${'$'}/, '').replace(/\.+${'$'}/, '').toLowerCase();
  }

  function isIpLiteral(host) {
    if (!host) return false;
    if (host.indexOf(':') !== -1) return /^[0-9a-f:.]+${'$'}/i.test(host);
    var parts = host.split('.');
    if (parts.length !== 4) return false;
    return parts.every(function(part) {
      if (!/^[0-9]{1,3}${'$'}/.test(part)) return false;
      var value = Number(part);
      return value >= 0 && value <= 255;
    });
  }

  function requiresHnsResolution(host) {
    host = normalizeHost(host);
    if (!host || reservedSingleLabels.has(host) || isIpLiteral(host)) return false;
    if (host.endsWith('.localhost')) return false;
    var labels = host.split('.');
    if (labels.length === 1) return true;
    return !icannTlds.has(labels[labels.length - 1]);
  }

  function inActiveHnsScope(targetHost, activeHost) {
    return targetHost === activeHost || targetHost.endsWith('.' + activeHost);
  }

  function bridgedUrl(rawUrl) {
    var pageUrl;
    var targetUrl;
    try {
      pageUrl = new URL(window.location.href);
      targetUrl = new URL(rawUrl, window.location.href);
    } catch (error) {
      return null;
    }

    if (pageUrl.protocol !== 'https:' && pageUrl.protocol !== 'http:') return null;
    if (targetUrl.protocol !== 'wss:' && targetUrl.protocol !== 'ws:') return null;
    if (pageUrl.protocol === 'https:' && targetUrl.protocol === 'ws:') return null;

    var pageHost = normalizeHost(pageUrl.hostname);
    var targetHost = normalizeHost(targetUrl.hostname);
    if (!requiresHnsResolution(pageHost) || !requiresHnsResolution(targetHost)) return null;
    if (!inActiveHnsScope(targetHost, pageHost)) return null;
    return targetUrl.href;
  }

  function protocolList(protocols) {
    if (protocols === undefined) return [];
    if (typeof protocols === 'string') return [protocols];
    return Array.prototype.slice.call(protocols).map(function(protocol) { return String(protocol); });
  }

  function post(payload) {
    bridge.postMessage(JSON.stringify(payload));
  }

  function eventWithProps(type, props) {
    var event;
    if (type === 'message' && typeof MessageEvent === 'function') {
      event = new MessageEvent('message', props || {});
    } else if (type === 'close' && typeof CloseEvent === 'function') {
      event = new CloseEvent('close', props || {});
    } else {
      event = document.createEvent('Event');
      event.initEvent(type, false, false);
      props = props || {};
      Object.keys(props).forEach(function(key) {
        try { Object.defineProperty(event, key, { value: props[key] }); } catch (ignored) { event[key] = props[key]; }
      });
    }
    return event;
  }

  function base64ToArrayBuffer(value) {
    var text = atob(value || '');
    var bytes = new Uint8Array(text.length);
    for (var index = 0; index < text.length; index++) bytes[index] = text.charCodeAt(index);
    return bytes.buffer;
  }

  function arrayBufferToBase64(buffer) {
    var bytes = new Uint8Array(buffer);
    var chunk = '';
    var output = '';
    for (var index = 0; index < bytes.length; index++) {
      chunk += String.fromCharCode(bytes[index]);
      if (chunk.length >= 8190) {
        output += btoa(chunk);
        chunk = '';
      }
    }
    return output + (chunk ? btoa(chunk) : '');
  }

  function HnsNativeWebSocket(url, protocols) {
    this.url = url;
    this.readyState = CONNECTING;
    this.bufferedAmount = 0;
    this.extensions = '';
    this.protocol = '';
    this.binaryType = 'blob';
    this.onopen = null;
    this.onmessage = null;
    this.onerror = null;
    this.onclose = null;
    this.__listeners = Object.create(null);
    this.__id = nextId++;
    sockets[this.__id] = this;
    post({ type: 'open', pageId: pageId, id: this.__id, url: url, protocols: protocolList(protocols) });
  }

  HnsNativeWebSocket.prototype.addEventListener = function(type, listener) {
    if (!listener) return;
    (this.__listeners[type] || (this.__listeners[type] = [])).push(listener);
  };

  HnsNativeWebSocket.prototype.removeEventListener = function(type, listener) {
    var listeners = this.__listeners[type];
    if (!listeners) return;
    this.__listeners[type] = listeners.filter(function(candidate) { return candidate !== listener; });
  };

  HnsNativeWebSocket.prototype.dispatchEvent = function(event) {
    var listeners = (this.__listeners[event.type] || []).slice();
    for (var index = 0; index < listeners.length; index++) {
      if (typeof listeners[index] === 'function') listeners[index].call(this, event);
      else if (listeners[index] && typeof listeners[index].handleEvent === 'function') listeners[index].handleEvent(event);
    }
    var handler = this['on' + event.type];
    if (typeof handler === 'function') handler.call(this, event);
    return !event.defaultPrevented;
  };

  HnsNativeWebSocket.prototype.send = function(data) {
    if (this.readyState === CONNECTING) throw new DOMException('WebSocket is still connecting.', 'InvalidStateError');
    if (this.readyState !== OPEN) return;
    if (typeof data === 'string') {
      this.bufferedAmount += data.length;
      post({ type: 'send', pageId: pageId, id: this.__id, dataType: 'text', data: data });
      return;
    }
    if (data instanceof ArrayBuffer || ArrayBuffer.isView(data)) {
      var buffer = data instanceof ArrayBuffer ? data : data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
      this.bufferedAmount += buffer.byteLength;
      post({ type: 'send', pageId: pageId, id: this.__id, dataType: 'binary', data: arrayBufferToBase64(buffer) });
      return;
    }
    if (typeof Blob !== 'undefined' && data instanceof Blob) {
      var socket = this;
      this.bufferedAmount += data.size;
      data.arrayBuffer().then(function(buffer) {
        if (socket.readyState === OPEN) {
          post({ type: 'send', pageId: pageId, id: socket.__id, dataType: 'binary', data: arrayBufferToBase64(buffer) });
        }
      });
      return;
    }
    post({ type: 'send', pageId: pageId, id: this.__id, dataType: 'text', data: String(data) });
  };

  HnsNativeWebSocket.prototype.close = function(code, reason) {
    if (this.readyState === CLOSING || this.readyState === CLOSED) return;
    if (code !== undefined && code !== 1000 && (code < 3000 || code > 4999)) {
      throw new DOMException('Invalid WebSocket close code.', 'InvalidAccessError');
    }
    reason = reason === undefined ? '' : String(reason);
    if (typeof TextEncoder === 'function' && new TextEncoder().encode(reason).length > 123) {
      throw new DOMException('WebSocket close reason is too long.', 'SyntaxError');
    }
    this.readyState = CLOSING;
    post({ type: 'close', pageId: pageId, id: this.__id, code: code || 1000, reason: reason });
  };

  HnsNativeWebSocket.prototype.__handleBridgeEvent = function(message) {
    if (message.event === 'open') {
      this.readyState = OPEN;
      this.protocol = message.protocol || '';
      this.dispatchEvent(eventWithProps('open'));
      return;
    }
    if (message.event === 'message') {
      var data = message.data || '';
      if (message.dataType === 'binary') {
        var buffer = base64ToArrayBuffer(data);
        data = this.binaryType === 'arraybuffer' ? buffer : new Blob([buffer]);
      }
      this.dispatchEvent(eventWithProps('message', { data: data, origin: window.location.origin || '' }));
      return;
    }
    if (message.event === 'error') {
      this.dispatchEvent(eventWithProps('error'));
      return;
    }
    if (message.event === 'close') {
      this.readyState = CLOSED;
      delete sockets[this.__id];
      this.dispatchEvent(eventWithProps('close', {
        code: message.code || 1006,
        reason: message.reason || '',
        wasClean: !!message.wasClean
      }));
    }
  };

  function WebSocketWrapper(url, protocols) {
    if (!(this instanceof WebSocketWrapper)) throw new TypeError("Failed to construct 'WebSocket': Please use the 'new' operator.");
    var urlText = bridgedUrl(url);
    if (!urlText) {
      return protocols === undefined ? new NativeWebSocket(url) : new NativeWebSocket(url, protocols);
    }
    return new HnsNativeWebSocket(urlText, protocols);
  }

  WebSocketWrapper.prototype = HnsNativeWebSocket.prototype;
  WebSocketWrapper.CONNECTING = CONNECTING;
  WebSocketWrapper.OPEN = OPEN;
  WebSocketWrapper.CLOSING = CLOSING;
  WebSocketWrapper.CLOSED = CLOSED;
  HnsNativeWebSocket.prototype.CONNECTING = CONNECTING;
  HnsNativeWebSocket.prototype.OPEN = OPEN;
  HnsNativeWebSocket.prototype.CLOSING = CLOSING;
  HnsNativeWebSocket.prototype.CLOSED = CLOSED;

  var onBridgeMessage = function(event) {
    var message;
    try { message = JSON.parse(event.data); } catch (error) { return; }
    if (message.pageId !== pageId) return;
    var socket = sockets[message.id];
    if (socket) socket.__handleBridgeEvent(message);
  };
  window.__hnsWebSocketDispatch = function(data) {
    onBridgeMessage({ data: data });
  };
  if (typeof bridge.addEventListener === 'function') bridge.addEventListener('message', onBridgeMessage);
  bridge.onmessage = onBridgeMessage;
  window.WebSocket = WebSocketWrapper;
})();
        """.trimIndent()
    }
}
