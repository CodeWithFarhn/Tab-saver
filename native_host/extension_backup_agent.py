import sys
import json
import struct
import time
from b2_client import b2_push, b2_pull

def read_message():
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length or len(raw_length) < 4:
        return None
    message_length = struct.unpack("<I", raw_length)[0]
    message_bytes = sys.stdin.buffer.read(message_length)
    if len(message_bytes) < message_length:
        return None
    return json.loads(message_bytes.decode("utf-8"))

def send_message(message):
    encoded_message = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(struct.pack("<I", len(encoded_message)))
    sys.stdout.buffer.write(encoded_message)
    sys.stdout.buffer.flush()

def main():
    while True:
        try:
            msg = read_message()
            if msg is None:
                break

            op = msg.get("op") or msg.get("type") or msg.get("action")

            if op == "ping":
                send_message({
                    "status": "ok",
                    "op": "pong",
                    "message": "NMH host is running and responding!",
                    "server_time": time.time(),
                })
            elif op == "push":
                payload = msg.get("payload") or msg.get("data")
                if not payload:
                    send_message({
                        "status": "error",
                        "error": "Missing payload for push operation",
                    })
                    continue
                # If payload is dict or object, serialize to json string
                if isinstance(payload, dict):
                    payload = json.dumps(payload)
                result = b2_push(payload)
                send_message(result)

            elif op == "pull":
                result = b2_pull()
                send_message(result)

            else:
                send_message({
                    "status": "error",
                    "error": f"Unknown operation: {op}",
                })
        except Exception as e:
            send_message({
                "status": "error",
                "error": str(e),
            })
            break

if __name__ == "__main__":
    main()
