using SoftwareSwitch;

var sw = new Switch();
var bridge = new RawSocketBridge(sw);
string host = args.Length >= 1 ? args[0] : "127.0.0.1";
int port = args.Length >= 2 && int.TryParse(args[1], out var p) ? p : 8080;

using var gui = new WebGui(sw, bridge, host, port);
gui.Start();
Console.WriteLine($"GUI running on http://{host}:{port}");
Console.WriteLine("Press Ctrl+C to exit.");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
try { await Task.Delay(Timeout.Infinite, cts.Token); } catch (OperationCanceledException) { }

bridge.Stop();
