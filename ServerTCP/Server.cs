using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Antihack;
using ext_encrypt_decrypt;
//using Newtonsoft.Json;
using json_ext;
using Newtonsoft.Json;
using SuperSimpleTcp;

namespace ServerTCP
{
    public partial class Form1 : Form
    {
        //
        private string pach = Directory.GetCurrentDirectory();
        private ClassJson json = new ClassJson();
        encrypt_decrypt crypt = new encrypt_decrypt();
        string serverIp,
            ipsw,
            key;
        int port,
            portsw;
        private SimpleTcpServer server;

        // Diccionario para mantener información de los clientes conectados
        private Dictionary<string, ClientInfo> connectedClients =
            new Dictionary<string, ClientInfo>();
        private Dictionary<string, bool> authenticatedClients = new Dictionary<string, bool>();
        private List<String> Mesag = new List<String>();

        // Modificar la clase ClientInfo para incluir un campo de última actividad
        private class ClientInfo
        {
            public string IpPort { get; set; }
            public DateTime ConnectedTime { get; set; }
            public DateTime LastActivityTime { get; set; } // Nuevo campo
            public string Status { get; set; }
            public int BytesReceived { get; set; }
            public int BytesSent { get; set; }
        }

        public Form1()
        {
            InitializeComponent();
            // Cargar configuración desde el archivo INI
            LoadDLL();
            // Inicializar el servidor con la IP y el puerto
            inputServerIp.Text = $"{serverIp}:{port}";
        }
        private void ScrollToBottom(TextBox textBox)
        {
            // Desactivar redibujado para evitar parpadeo
            textBox.SuspendLayout();

            // Mover el cursor al final
            textBox.SelectionStart = textBox.TextLength;
            textBox.SelectionLength = 0;

            // Desplazar hasta el cursor (final)
            textBox.ScrollToCaret();

            // Reactivar redibujado
            textBox.ResumeLayout();
        }
        private void LoadDLL()
        {
            INIFile tx = new INIFile($"{pach}\\Config.ini");
            serverIp = tx.IniReadValue("CONFIG", "IP");
            port = int.Parse(tx.IniReadValue("CONFIG", "PORT"));
            key = tx.IniReadValue("CONFIG", "KEY");

            ipsw = tx.IniReadValue("server", "host");
            portsw = int.Parse(tx.IniReadValue("server", "port"));
            //hwid = crypt.decrypt(tx.IniReadValue("CONFIG", "HWID"));
        }

        private void Server_Load(object sender, EventArgs e)
        {
            InitializeServer();
        }

        private void InitializeServer()
        {
            inputSelect.SelectedIndex = 0;
            btnSend.Enabled = false;

            server = new SimpleTcpServer(serverIp, port);
            // Configuración mejorada
            server.Settings.MaxConnections = 1000;
            server.Settings.NoDelay = true;
            server.Keepalive = new SimpleTcpKeepaliveSettings
            {
                EnableTcpKeepAlives = true,
                TcpKeepAliveInterval = 5,
                TcpKeepAliveTime = 5,
                TcpKeepAliveRetryCount = 5,
            };

            server.Events.ClientConnected += Events_ClientConnected;
            server.Events.ClientDisconnected += Events_ClientDisconnected;
            server.Events.DataReceived += Events_DataReceived;

            // Agregar temporizador para actualizar estadísticas
            Timer statsTimer = new Timer();
            statsTimer.Interval = 1000; // Actualizar cada segundo
            statsTimer.Tick += UpdateClientStats;
            statsTimer.Start();

            Timer idleTimer = new Timer();
            idleTimer.Interval = 1000; // 1 minuto
            idleTimer.Tick += CheckIdleConnections;
            idleTimer.Start();
        }

        // Modificar CheckIdleConnections para usar LastActivityTime
        private void CheckIdleConnections(object sender, EventArgs e)
        {
            var now = DateTime.Now;
            var toDisconnect = new List<string>();

            foreach (var client in connectedClients)
            {
                // Desconectar clientes sin autenticar después de 30 segundos
                if (
                    !authenticatedClients.ContainsKey(client.Key)
                    || !authenticatedClients[client.Key]
                )
                {
                    if ((now - client.Value.ConnectedTime).TotalSeconds > 30)
                    {
                        toDisconnect.Add(client.Key);
                    }
                }
                // Desconectar clientes inactivos después de 15 minutos de inactividad real
                else if ((now - client.Value.LastActivityTime).TotalMinutes > 15)
                {
                    toDisconnect.Add(client.Key);
                    inputInfo.Text +=
                        $"Disconnected idle client after 15 min inactivity: {client.Key}{Environment.NewLine}";
                }
            }

            foreach (var ipPort in toDisconnect)
            {
                server.DisconnectClient(ipPort);
                inputInfo.Text += $"Disconnected idle client: {ipPort}{Environment.NewLine}";
            }
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            try
            {
                server.Start();
                inputServerIp.Text = $"{serverIp}:{port}";
                inputInfo.Text += $"Server started on {serverIp}:{port}{Environment.NewLine}";
                btnStart.Enabled = false;
                btnSend.Enabled = true;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error starting server: {ex.Message}");
            }
        }

        private void Events_ClientConnected(object sender, ConnectionEventArgs e)
        {
            this.Invoke(
                (MethodInvoker)
                    delegate
                    {
                        // Verificar lista negra
                        if (IsIpBlacklisted(e.IpPort))
                        {
                            server.DisconnectClient(e.IpPort);
                            inputInfo.Text +=
                                $"Blocked connection from blacklisted IP: {e.IpPort}{Environment.NewLine}";
                            return;
                        }

                        // En Events_ClientConnected, inicializar LastActivityTime
                        connectedClients[e.IpPort] = new ClientInfo
                        {
                            IpPort = e.IpPort,
                            ConnectedTime = DateTime.Now,
                            LastActivityTime = DateTime.Now, // Inicializar al mismo tiempo que ConnectedTime
                            Status = "Connected",
                            BytesReceived = 0,
                            BytesSent = 0,
                        };

                        //inputInfo.Text += $"New client connected: {e.IpPort}{Environment.NewLine}";
                        lstClientIP.Items.Add(e.IpPort);
                    }
            );
        }

        private bool IsIpBlacklisted(string ipPort)
        {
            string[] blacklistedIps = json.Blacklist().IP.Split(',');
            string clientIp = ipPort.Split(':')[0];
            return blacklistedIps.Contains(clientIp);
        }

        private void Events_ClientDisconnected(object sender, SuperSimpleTcp.ConnectionEventArgs e)
        {
            this.Invoke(
                (MethodInvoker)
                    delegate
                    {
                        if (connectedClients.ContainsKey(e.IpPort))
                        {
                            connectedClients.Remove(e.IpPort);
                        }

                        if (authenticatedClients.ContainsKey(e.IpPort))
                        {
                            authenticatedClients.Remove(e.IpPort);
                        }

                        inputInfo.Text += $"Client disconnected: {e.IpPort}{Environment.NewLine}";
                        lstClientIP.Items.Remove(e.IpPort);
                    }
            );
            UpdateServerStats();
        }

        private void Events_DataReceived(object sender, SuperSimpleTcp.DataReceivedEventArgs e) => this.Invoke(
                (MethodInvoker)
                    delegate
                    {
                        if (connectedClients.ContainsKey(e.IpPort))
                        {
                            connectedClients[e.IpPort].LastActivityTime = DateTime.Now; // Actualizar cada vez que se reciben datos
                            connectedClients[e.IpPort].BytesReceived += e.Data.Count;
                        }
                        // Mostrar datos recibidos en el TextBox
                        byte[] rawData = e
                            .Data.Array.Skip(e.Data.Offset)
                            .Take(e.Data.Count)
                            .ToArray();
                        string receivedData = Encoding.UTF8.GetString(rawData);
                        dynamic obj = JsonConvert.DeserializeObject(receivedData);
                        string action = obj.action;

                        // Verificar autenticación primero
                        if (
                            !authenticatedClients.ContainsKey(e.IpPort)
                            || !authenticatedClients[e.IpPort]
                        )
                        {
                            if (action == "AUTH")
                            {
                                string clientKey = obj.key;
                                string clientHwid = obj.hwid;

                                // Validar la clave del cliente
                                if (clientKey == key) // 'key' es la clave del servidor cargada desde el INI
                                {
                                    authenticatedClients[e.IpPort] = true;
                                    inputInfo.Text +=
                                        $"Client authenticated: {e.IpPort}{Environment.NewLine}";

                                    // Responder con éxito de autenticación
                                    var response = new
                                    {
                                        action = "AUTH_RESPONSE",
                                        status = "success",
                                        message = "Authentication successful",
                                    };
                                    server.Send(e.IpPort, JsonConvert.SerializeObject(response));
                                    return;
                                }
                                else
                                {
                                    server.DisconnectClient(e.IpPort);
                                    return;
                                }
                            }
                        }

                        switch (action)
                        {
                            case "HEARTBEAT":
                                {
                                    if (connectedClients.ContainsKey(e.IpPort))
                                    {
                                        connectedClients[e.IpPort].LastActivityTime = DateTime.Now;
                                    }
                                }
                                break;
                            case "INIT":
                                {
                                    string user_id = obj.user_id;
                                    string hwid = obj.hwid;

                                    inputInfo.Text += $"{action} | HWID: {hwid}| IP: {e.IpPort}| USERID: {user_id}{Environment.NewLine}";
                                }
                                break;
                            case "STREAMVIEWER":
                                {
                                    string message = obj.message;
                                    string user_id = obj.user_id;
                                    inputInfo.Text += $"{action} | MSG: {message}| IP: {e.IpPort}| USERID: {user_id}{Environment.NewLine}";
                                }
                                break;
                            case "CHEAT_REPORT":
                                {
                                    string user_id = obj.user_id;
                                    string process = obj.process;
                                    textBox_playes_report.Text += $"{action} | PROCESS: {process}| IP: {e.IpPort}| USERID: {user_id}{Environment.NewLine}";
                                }
                                break;
                            case "THREAT":
                                {
                                    string message = obj.message;
                                    string user_id = obj.user_id;
                                    textBox_playes_report.Text += $"{action} | MSG: {message}| IP: {e.IpPort}| USERID: {user_id}{Environment.NewLine}";
                                }
                                break;
                            case "REPORT_DLL":
                                {
                                    string message = obj.message;
                                    string user_id = obj.user_id;
                                    textBox_playes_report.Text += $"{action} | MSG: {message}| IP: {e.IpPort}| USERID: {user_id}{Environment.NewLine}";
                                    //server.DisconnectClient(e.IpPort);
                                }
                                break;
                            case "INJECTION_ALERT":
                                {
                                    string message = obj.message;
                                    string user_id = obj.user_id;
                                    textBox_playes_report.Text += $"{action} | MSG: {message} | IP: {e.IpPort}| USERID: {user_id}{Environment.NewLine}";
                                    //server.DisconnectClient(e.IpPort);
                                }
                                break;
                            default:
                                break;
                        }

                        ScrollToBottom(inputInfo);
                        ScrollToBottom(textBox_playes_report);
                        //inputInfo.Text += $"Data from {e.IpPort}: {receivedData}{Environment.NewLine}";

                        // Actualizar estadísticas globales
                        UpdateServerStats();
                    }
            );

        private void UpdateServerStats()
        {
            int authenticatedCount = authenticatedClients.Count(c => c.Value);
            long totalBytesReceived = server.Statistics.ReceivedBytes;
            long totalBytesSent = server.Statistics.SentBytes;

            toolStripStatusLabel2.Text =
                $"Authenticated Clients: {authenticatedCount} | Received: {FormatBytes(totalBytesReceived)} | Sent: {FormatBytes(totalBytesSent)}";
        }

        private void UpdateClientStats(object sender, EventArgs e)
        {
            // Actualizar información de clientes cada segundo
            foreach (var client in connectedClients.Values)
            {
                TimeSpan duration = DateTime.Now - client.ConnectedTime;
                client.Status = $"Connected ({duration.ToString(@"hh\:mm\:ss")})";
            }
        }

        private void searchBox_TextChanged(object sender, EventArgs e)
        {
            string textoBusqueda = searchBox.Text.ToLower();
            var filter = connectedClients
                .Where(c => c.ToString().ToLower().Contains(textoBusqueda))
                .Select(c => c.Key) // Solo tomamos la IP
                .ToArray();

            lstClientIP.Items.Clear();
            lstClientIP.Items.AddRange(filter);
        }

        private string FormatBytes(long bytes)
        {
            string[] suffix = { "B", "KB", "MB", "GB" };
            int i = 0;
            double dblBytes = bytes;

            while (dblBytes >= 1024 && i < suffix.Length - 1)
            {
                dblBytes /= 1024;
                i++;
            }

            return $"{dblBytes:0.##} {suffix[i]}";
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            if (!server.IsListening)
            {
                MessageBox.Show("Server is not running");
                return;
            }

            if (inputSelect.SelectedIndex == 0 || lstClientIP.SelectedItem == null)
            {
                MessageBox.Show("Please select a client and an action");
                return;
            }

            string selectedClient = lstClientIP.SelectedItem.ToString();
            string postData;

            switch (inputSelect.SelectedIndex)
            {
                case 1: // Shutdown
                    postData = JsonConvert.SerializeObject(new { action = "shutdown" });
                    SendToClient(selectedClient, postData, "shutdown");
                    break;
                case 2: // Disconnect
                    //postData = JsonConvert.SerializeObject(new
                    //{
                    //    action = "disconnect",
                    //    key = key
                    //});
                    //SendToClient(selectedClient, postData, "disconnect");
                    server.DisconnectClient(selectedClient);
                    break;
                case 3: // Stream viewer

                    postData = JsonConvert.SerializeObject(
                        new
                        {
                            action = "streamviewer",
                            ip = ipsw,
                            port = portsw,
                            executable = "StreamClient.exe",
                        }
                    );
                    SendToClient(selectedClient, postData, "streamviewer");
                    break;
            }
        }

        private void SendToClient(string clientIp, string data, string action)
        {
            try
            {
                server.Send(clientIp, data);
                // También en SendToClient, actualizar LastActivityTime
                if (connectedClients.ContainsKey(clientIp))
                {
                    connectedClients[clientIp].LastActivityTime = DateTime.Now; // Actualizar cada vez que se envían datos
                    connectedClients[clientIp].BytesSent += Encoding.UTF8.GetBytes(data).Length;
                }

                inputInfo.Text += $"Sent {action} command to {clientIp}{Environment.NewLine}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error sending data to client: {ex.Message}");
            }
        }
    }
}
