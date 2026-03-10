using System.Net;
using System.Text;
using System.Web;

namespace SoftwareSwitch;

/// <summary>
/// Minimal HTTP GUI served via <see cref="HttpListener"/>.
/// Provides pages to start/stop the raw-socket bridge, process test frames,
/// view the MAC table (with TTL), manage MAC table settings, and reset stats.
/// </summary>
public sealed class WebGui : IDisposable
{
    private readonly Switch _switch;
    private readonly RawSocketBridge _bridge;
    private readonly HttpListener _listener;
    private readonly Thread _serveThread;
    private volatile bool _running;
    private string _lastMessage = string.Empty;

    public WebGui(Switch sw, RawSocketBridge bridge, string host = "127.0.0.1", int port = 8080)
    {
        _switch = sw;
        _bridge = bridge;
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://{host}:{port}/");
        _serveThread = new Thread(ServeLoop) { IsBackground = true, Name = "WebGuiServe" };
    }

    public void Start()
    {
        _listener.Start();
        _running = true;
        _serveThread.Start();
    }

    public void Stop()
    {
        _running = false;
        _listener.Stop();
        _serveThread.Join(TimeSpan.FromSeconds(2));
    }

    // -------------------------------------------------------------------------
    // HTTP dispatch
    // -------------------------------------------------------------------------

    private void ServeLoop()
    {
        while (_running)
        {
            HttpListenerContext ctx;
            try { ctx = _listener.GetContext(); }
            catch (HttpListenerException) { break; }
            catch (ObjectDisposedException) { break; }

            try { HandleRequest(ctx); }
            catch (Exception ex) { SetMessage($"Internal error: {ex.Message}"); }
        }
    }

    private void HandleRequest(HttpListenerContext ctx)
    {
        var req = ctx.Request;
        var resp = ctx.Response;
        string path = req.Url?.AbsolutePath ?? "/";

        if (req.HttpMethod == "GET" && path == "/")
        {
            SendHtml(resp, RenderPage());
            return;
        }

        if (req.HttpMethod == "POST")
        {
            string body = new System.IO.StreamReader(req.InputStream, req.ContentEncoding).ReadToEnd();
            var form = ParseForm(body);

            switch (path)
            {
                case "/process":
                    HandleProcessFrame(form);
                    break;
                case "/reset":
                    _switch.ResetStatistics();
                    SetMessage("Statistics reset.");
                    break;
                case "/bridge/start":
                    HandleBridgeStart(form);
                    break;
                case "/bridge/stop":
                    _bridge.Stop();
                    SetMessage("Bridge stopped.");
                    break;
                case "/mac/clear":
                    _switch.ClearMacTable();
                    SetMessage("MAC table cleared.");
                    break;
                case "/mac/set_ttl":
                    HandleSetTtl(form);
                    break;
                default:
                    Send404(resp);
                    return;
            }

            resp.StatusCode = 303;
            resp.Headers["Location"] = "/";
            resp.Close();
            return;
        }

        Send404(resp);
    }

    // -------------------------------------------------------------------------
    // Action handlers
    // -------------------------------------------------------------------------

    private void HandleProcessFrame(Dictionary<string, string> form)
    {
        int inPort = int.TryParse(form.GetValueOrDefault("in_port"), out var p) ? p : 1;
        string hexFrame = form.GetValueOrDefault("frame_hex") ?? string.Empty;
        byte[] frame = ParseHexFrame(hexFrame);
        var result = _switch.ProcessFrame(inPort, frame);
        SetMessage(
            $"Frame processed: in={result.InPort} out={result.OutPort} " +
            $"src={result.SrcMac} dst={result.DstMac} " +
            $"protocols={string.Join(",", result.Protocols)}");
    }

    private void HandleBridgeStart(Dictionary<string, string> form)
    {
        string iface1 = form.GetValueOrDefault("port1_iface") ?? string.Empty;
        string iface2 = form.GetValueOrDefault("port2_iface") ?? string.Empty;
        _bridge.Start(iface1, iface2);
        SetMessage($"Bridge started on {iface1} <-> {iface2}");
    }

    private void HandleSetTtl(Dictionary<string, string> form)
    {
        if (!int.TryParse(form.GetValueOrDefault("ttl"), out int ttl))
            ttl = Switch.DefaultMacTtlSeconds;
        _switch.SetMacTtl(ttl);
        SetMessage($"MAC TTL set to {ttl} s.");
    }

    // -------------------------------------------------------------------------
    // HTML rendering
    // -------------------------------------------------------------------------

    private string RenderPage()
    {
        var snapshot = _switch.MacTableSnapshot();
        int macTtl = _switch.MacTtlSeconds;
        bool bridgeRunning = _bridge.IsRunning;
        string bridgeInfo = bridgeRunning
            ? $" ({HE(_bridge.Port1Interface)} &lt;-&gt; {HE(_bridge.Port2Interface)})"
            : string.Empty;

        var ifaceOptions = new StringBuilder();
        foreach (var iface in Switch.AvailableInterfaces())
            ifaceOptions.Append($"<option value='{HE(iface)}'>{HE(iface)}</option>");
        if (ifaceOptions.Length == 0)
            ifaceOptions.Append("<option value=''>No interfaces found</option>");

        var macRows = new StringBuilder();
        foreach (var (mac, port, lifetime) in snapshot)
            macRows.Append($"<tr><td>{HE(mac)}</td><td>{port}</td><td>{lifetime:F0}</td></tr>");
        if (macRows.Length == 0)
            macRows.Append("<tr><td colspan='3'>empty</td></tr>");

        var statsRows = new StringBuilder();
        foreach (var portNum in new[] { 1, 2 })
        {
            var s = _switch.Stats[portNum];
            foreach (var proto in PortStatistics.Protocols)
            {
                statsRows.Append(
                    $"<tr><td>{portNum}</td><td>{proto}</td>" +
                    $"<td>{s.RxPdus[proto]}</td>" +
                    $"<td>{s.TxPdus[proto]}</td></tr>");
            }
        }

        return $$"""
            <!doctype html>
            <html>
            <head>
              <meta charset="utf-8" />
              <title>Software Switch GUI (C#)</title>
              <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; margin-bottom: 16px; }
                th, td { border: 1px solid #aaa; padding: 6px 10px; }
                .msg { margin: 10px 0; padding: 8px; background: #f3f7ff; }
                textarea { width: 100%; max-width: 800px; }
              </style>
            </head>
            <body>
              <h1>Software Switch (C# Prototype)</h1>
              <div class="msg">{{HE(_lastMessage)}}</div>

              <h2>Physical bridge mode</h2>
              <div>Bridge status: {{(bridgeRunning ? "running" : "stopped")}}{{bridgeInfo}}</div>
              <form method="post" action="/bridge/start">
                <label>Port 1 interface:</label>
                <select name="port1_iface">{{ifaceOptions}}</select>
                <label>Port 2 interface:</label>
                <select name="port2_iface">{{ifaceOptions}}</select>
                <button type="submit">Start bridge</button>
              </form>
              <form method="post" action="/bridge/stop" style="margin-top:10px;">
                <button type="submit">Stop bridge</button>
              </form>

              <h2>Process Frame (manual test)</h2>
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
              <p>TTL: {{macTtl}} s &nbsp;
                <form method="post" action="/mac/set_ttl" style="display:inline">
                  <input type="number" name="ttl" min="1" max="86400" value="{{macTtl}}" style="width:70px" />
                  <button type="submit">Set TTL</button>
                </form>
                &nbsp;
                <form method="post" action="/mac/clear" style="display:inline">
                  <button type="submit">Clear MAC table</button>
                </form>
              </p>
              <table>
                <tr><th>MAC address</th><th>Port</th><th>Lifetime (s)</th></tr>
                {{macRows}}
              </table>

              <h2>Protocol statistics</h2>
              <table>
                <tr><th>Port</th><th>Protocol</th><th>RX</th><th>TX</th></tr>
                {{statsRows}}
              </table>
            </body>
            </html>
            """;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private void SetMessage(string msg) => _lastMessage = msg;

    private static string HE(string? s) => HttpUtility.HtmlEncode(s ?? string.Empty);

    private static void SendHtml(HttpListenerResponse resp, string html)
    {
        byte[] body = Encoding.UTF8.GetBytes(html);
        resp.StatusCode = 200;
        resp.ContentType = "text/html; charset=utf-8";
        resp.ContentLength64 = body.Length;
        resp.OutputStream.Write(body);
        resp.Close();
    }

    private static void Send404(HttpListenerResponse resp)
    {
        byte[] body = "<h1>Not found</h1>"u8.ToArray();
        resp.StatusCode = 404;
        resp.ContentType = "text/html; charset=utf-8";
        resp.ContentLength64 = body.Length;
        resp.OutputStream.Write(body);
        resp.Close();
    }

    private static Dictionary<string, string> ParseForm(string body)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in body.Split('&'))
        {
            int eq = pair.IndexOf('=');
            if (eq < 0) continue;
            string key = Uri.UnescapeDataString(pair[..eq].Replace('+', ' '));
            string val = Uri.UnescapeDataString(pair[(eq + 1)..].Replace('+', ' '));
            result[key] = val;
        }
        return result;
    }

    /// <summary>Converts a hex-encoded string (spaces allowed) to a byte array.</summary>
    public static byte[] ParseHexFrame(string hex)
    {
        string cleaned = hex.Replace(" ", "").Replace("\n", "").Replace("\r", "").Replace("\t", "");
        if (cleaned.Length % 2 != 0)
            throw new ArgumentException("Frame hex string must contain an even number of characters.");
        try
        {
            return Convert.FromHexString(cleaned);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Frame hex string contains invalid hexadecimal characters.", ex);
        }
    }

    public void Dispose() => Stop();
}
