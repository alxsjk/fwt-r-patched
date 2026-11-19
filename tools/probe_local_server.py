"""Talks to the embedded offline server instead of the game client.

The shipped ``libfwt_local_server.so`` answers plain HTTP/1.1 on
``127.0.0.1:8010`` with a raw-DEFLATE JSON body (see the architecture guide,
section 3.4). This probe sends the same packets the client sends, so a handler
can be exercised without driving the UI:

    adb forward tcp:18010 tcp:8010
    python tools/probe_local_server.py --cmd GET_MY_INFO
    python tools/probe_local_server.py --dg-code 950233 --mail-idx 1484

``--dg-code`` sends ``RIDDLE_START`` (the VIP ticket dungeon entry); without it
the packet is a generic ``--cmd`` request. ``--lord-idx`` and ``--access-code``
default to the values recorded in the reference save.
"""

from __future__ import annotations

import argparse
import http.client
import json
import zlib

DEFAULT_LORD_IDX = 993838
DEFAULT_ACCESS_CODE = "local-access-code"
DEFAULT_MAIL_IDX = 1484


def build_packet(args: argparse.Namespace, packet_no: int) -> dict[str, object]:
    """Builds the request body for one probe call."""
    if args.dg_code is not None:
        # Field order follows the server's ExactJsonAccess list.
        return {
            "CMD": "RIDDLE_START",
            "packet_no": packet_no,
            "lord_idx": args.lord_idx,
            "access_code": args.access_code,
            "req_recommend_friend": True,
            "dg_code": args.dg_code,
            "combat_power": 0,
            "num_hero": 0,
            "mail_idx": args.mail_idx,
        }
    return {
        "lord_idx": args.lord_idx,
        "access_code": args.access_code,
        "CMD": args.cmd,
        "packet_no": packet_no,
    }


def post(port: int, payload: dict[str, object], user_index: int) -> tuple[int, str]:
    """Sends one packet and returns ``(status, body)``."""
    body = zlib.compress(json.dumps(payload, separators=(",", ":")).encode(), 1)[2:-4]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        conn.request(
            "POST",
            "/",
            body=body,
            headers={
                "accept": "application/json",
                "accept-charset": "utf-8",
                "accept-encoding": "deflate",
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Unity-Version": "2019.4.40f1",
                "user_index": str(user_index),
                "User-Agent": (
                    "UnityPlayer/2019.4.40f1 "
                    "(UnityWebRequest/1.0, libcurl/7.80.0-DEV)"
                ),
            },
        )
        response = conn.getresponse()
        return response.status, response.read().decode("utf-8", "replace")
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cmd", default="GET_MY_INFO", help="command for a generic packet")
    parser.add_argument("--dg-code", default=None, help="send RIDDLE_START for this dg_code")
    parser.add_argument("--mail-idx", type=int, default=DEFAULT_MAIL_IDX)
    parser.add_argument("--lord-idx", type=int, default=DEFAULT_LORD_IDX)
    parser.add_argument("--access-code", default=DEFAULT_ACCESS_CODE)
    parser.add_argument("--packet-no", type=int, default=901)
    parser.add_argument("--port", type=int, default=18010, help="forwarded local port")
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the raw response body instead of the first 200 characters",
    )
    args = parser.parse_args()

    payload = build_packet(args, packet_no=args.packet_no)
    status, body = post(args.port, payload, args.lord_idx)
    print(f"HTTP {status}")
    print(body if args.json else body[:200])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
