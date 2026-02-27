from __future__ import annotations

from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from software_switch import PROTOCOLS, SoftwareSwitch


def parse_hex_frame(raw: str) -> bytes:
    cleaned = "".join(raw.split())
    if len(cleaned) % 2 != 0:
        raise ValueError("Frame hex string must contain an even number of characters")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError("Frame hex string contains invalid hexadecimal characters") from exc


class SwitchGuiHandler(BaseHTTPRequestHandler):
    switch = SoftwareSwitch()
    last_result: str = ""

    def _write_html(self, html: str, status: int = 200) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _render(self) -> str:
        rows_mac = "".join(
            f"<tr><td>{escape(mac)}</td><td>{port}</td></tr>"
            for mac, port in sorted(self.switch.mac_table.items())
        )
        if not rows_mac:
            rows_mac = "<tr><td colspan='2'>empty</td></tr>"

        rows_stats = ""
        for port in (1, 2):
            for protocol in PROTOCOLS:
                rows_stats += (
                    f"<tr><td>{port}</td><td>{protocol}</td>"
                    f"<td>{self.switch.stats[port].rx_pdus[protocol]}</td>"
                    f"<td>{self.switch.stats[port].tx_pdus[protocol]}</td></tr>"
                )

        return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Software Switch GUI</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; }}
    table {{ border-collapse: collapse; margin-bottom: 16px; }}
    th, td {{ border: 1px solid #aaa; padding: 6px 10px; }}
    .msg {{ margin: 10px 0; padding: 8px; background: #f3f7ff; }}
    textarea {{ width: 100%; max-width: 800px; }}
  </style>
</head>
<body>
  <h1>Software Switch (Lab 3 GUI)</h1>
  <div class="msg">{escape(self.last_result)}</div>
  <h2>Process Frame</h2>
  <form method="post" action="/process">
    <label>Input port:</label>
    <select name="in_port"><option value="1">1</option><option value="2">2</option></select><br/><br/>
    <label>Ethernet frame (hex):</label><br/>
    <textarea name="frame_hex" rows="5" placeholder="00112233445566778899aabb0806..."></textarea><br/><br/>
    <button type="submit">Process frame</button>
  </form>
  <form method="post" action="/reset" style="margin-top:10px;">
    <button type="submit">Reset statistics</button>
  </form>

  <h2>MAC table</h2>
  <table>
    <tr><th>MAC address</th><th>Port</th></tr>
    {rows_mac}
  </table>

  <h2>Protocol statistics</h2>
  <table>
    <tr><th>Port</th><th>Protocol</th><th>RX</th><th>TX</th></tr>
    {rows_stats}
  </table>
</body>
</html>"""

    def do_GET(self) -> None:
        if self.path != "/":
            self._write_html("<h1>Not found</h1>", status=404)
            return
        self._write_html(self._render())

    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(content_length).decode("utf-8")
        form = parse_qs(payload)

        try:
            if self.path == "/process":
                in_port = int(form.get("in_port", ["1"])[0])
                frame = parse_hex_frame(form.get("frame_hex", [""])[0])
                result = self.switch.process_frame(in_port, frame)
                self.last_result = (
                    f"Frame processed: in={result['in_port']} out={result['out_port']} "
                    f"src={result['src_mac']} dst={result['dst_mac']} protocols={','.join(result['protocols'])}"
                )
            elif self.path == "/reset":
                self.switch.reset_statistics()
                self.last_result = "Statistics reset."
            else:
                self._write_html("<h1>Not found</h1>", status=404)
                return
        except Exception as exc:  # noqa: BLE001
            self.last_result = f"Error: {exc}"

        self.send_response(303)
        self.send_header("Location", "/")
        self.end_headers()


def run_gui(host: str = "127.0.0.1", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), SwitchGuiHandler)
    print(f"GUI running on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_gui()
