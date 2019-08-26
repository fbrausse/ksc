Signal Service Websocket API
============================

Conventions
-----------
- '<-': client to server
- '->': server to client
- all messages transferred over a websocket connection are protobuf-encoded
  'WebSocketMessage'-s containing either a 'request' or a 'response'.
- 'response'-s to 'request'-s are identified by the 'id' header in both types
  of messages. If it is missing in a request, no response is required.

Connections to text-secure.whispersystems.org
---------------------------------------------
- HTTPS with a pinned self-signed certificate available PEM-encoded in the file
  'whisper.store.asn1'.

'Provisioning' websocket connection
-----------------------------------
- established by HTTPS request to '/v1/websocket/provisioning/' including the
  'Upgrade' HTTP header for websocket.
- server directly sends a protobuf-encoded 'WebSocketMessage' containing a
  'WebSocketRequest' message with 'path' being '/v1/address'.
- its 'body' is a protobuf-encoded 'ProvisioningUuid' message.
- further state of this protocol unknown

'Service' websocket connection
------------------------------
- established by HTTPS connection, followed by a request to
  '/v1/websocket/?login=LOGIN&password=PASS' including the 'Upgrade' HTTP
  header for websocket.
- LOGIN is either NUMBER or NUMBER.DEVICE-ID if the device-ID is present.
- the default device-ID is 1.

-> PUT /api/v1/message
----------------------
- expects a '200 OK' response
- encrypted unless header 'X-Signal-Key: false' is present
  - decrypt/verify using the 'signalingKey' (a pair of a AES-CBC-PKCS5Padding
    key + 20 byte SHA256-HMAC key)
- 'body' is a protobuf-encoded 'Envelope', containing 'source', 'sourcedevice',
  'timestamp' and a 'content' of type 'ciphertext' or 'prekey bundle'
  (purpose of others not identified, yet)
- 'content' is encrypted using the Signal protocol and contains a protobuf-
  encoded 'Content'.
- 'Content' contains one of various sorts of messages; a 'datamessage', is a
  standard message; a 'prekey bundle' can optionally hold a 'datamessage' as
  well.
- a 'datamessage' has a 'body' (the message's text), optional 'group' info,
  some 'flags', another 'timestamp' and additional optional fields.

-> PUT /api/v1/queue/empty
--------------------------
- sent by the server when it has no more messages waiting.

<- PUT /v1/messages/NUMBER
--------------------------
- header: Content-Type: application/json
- body is a JSON object (see OutgoingPushMessage.java in libsignal-service-java
  for reference) with the following fields:
  - `String destination`: NUMBER
  - `long timestamp`: milli-seconds since the epoch
  - `messages`: array of JSON objects (see OutgoingPushMessage.java for
    reference):
    - `int type`
    - `int destinationDeviceId`
    - `int destinationRegistrationId`
    - `String content` holds the base64-encoded ciphertext resulting from
      encrypting an unpadded protobuf-encoded Content message with the
      session-cipher for the the (name,deviceId) tuple.
  - `boolean online`

<- GET /v1/messages/
--------------------
- response is JSON-encoded.
  - 'messages': an array of JSON-encoded 'Envelope'-s whose 'content' (see
    PUT /api/v1/message) is stored base64-encoded.
  - 'more': a boolean field signifying whether another GET request would
    obtain more messages.

<- GET /v1/keepalive
--------------------
- sent after 55 seconds, returns '200 OK'

<- DELETE /v1/messages/MESSAGE-IDENT
------------------------------------
- MESSAGE-IDENT is 'SOURCE/TIMESTAMP' or 'uuid/SERVER-GUID' with SOURCE,
  TIMESTAMP and SERVER-GUID from the message's 'Envelope'.
- works after sending the response to 'PUT /api/v1/message' or after a
  'GET /v1/messages/' request.
- response is '204 No Content'.
