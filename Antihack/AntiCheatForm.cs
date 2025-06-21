using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using AntiCheat.Properties;
using HardwareIds.NET.Structures;
using Microsoft.Win32;
using Newtonsoft.Json;
using SuperSimpleTcp;

namespace AntiCheat
{
    public partial class AntiCheatForm : Form
    {
        private readonly string logFilePath = Path.Combine(
            Directory.GetCurrentDirectory(),
            "antihack.log"
        );
        private const int LOADING_BAR_MAX_WIDTH = 492;

        private readonly string pach = Directory.GetCurrentDirectory();
        private readonly encrypt_decrypt crypt = new encrypt_decrypt();
        private readonly ProcessStartInfo gameStartInfo = new ProcessStartInfo();
        private readonly List<string> blacklistedProcesses;

        private SimpleTcpClient client;
        private int port;
        private int loadingProgress = 0;
        private string serverIp,
            keyrecep,
            game;
        private Timer heartbeatTimer;

        //private bool isGameRunning = false;

        private string[] arguments = null;

        public AntiCheatForm(string[] args)
        {
            //int versionMinimaRequerida = 528049; // .NET Framework 4.8
            //int versionInstalada = ObtenerVersionDotNet();

            //if (versionInstalada >= versionMinimaRequerida) ;
            //else
            //{
            //    MessageBox.Show(
            //    "ERROR: Se requiere .NET Framework 4.8 o superior.\n" +
            //    "Versión instalada: " + versionInstalada + "\n" +
            //    "Descárgalo desde:\nhttps://dotnet.microsoft.com/en-us/download/dotnet-framework/net48",
            //    "Error de Compatibilidad",
            //    MessageBoxButtons.OK,
            //    MessageBoxIcon.Error
            //    );
            //    // Opcional: cerrar el programa
            //    Environment.Exit(1);

            //}

            if (args.Length < 2 || args.Length <= 0)
            {
                this.Close();
                MessageBox.Show("Invalid arguments. Please provide the correct parameters.");
                Application.Exit();
            }
            else
            {
                arguments = args;
                InitializeComponent();
                blacklistedProcesses = InitializeBlacklistedProcesses();
            }
        }

        static int ObtenerVersionDotNet()
        {
            using (
                RegistryKey clave = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\"
                )
            )
            {
                if (clave != null && clave.GetValue("Release") != null)
                {
                    return (int)clave.GetValue("Release");
                }
                else
                {
                    return 0; // No está instalado
                }
            }
        }

        private void InitializeTimers()
        {
            timer1 = new Timer();
            timer2 = new Timer();
            heartbeatTimer = new Timer(); // Nuevo timer para heartbeat

            timer1.Tick += timer1_Tick;
            timer2.Tick += timer2_Tick;
            heartbeatTimer.Tick += heartbeatTimer_Tick;

            // Configurar el intervalo del heartbeat (cada 2 minutos)
            heartbeatTimer.Interval = 120000; // 2 minutos en milisegundos
        }

        private bool isServerRunning = false;
        private List<string> pendingMessages = new List<string>();

        // Reemplaza el método getHwid con esta implementación más robusta
        private string getHwid()
        {
            try
            {
                // Intentar obtener HWID con la biblioteca HardwareIds.NET
                var ids = HardwareIds.NET.HardwareIds.GetHwid();

                if (ids != null && ids.Motherboard != null && ids.Motherboard.UUID != null)
                {
                    string hwid = ids.Motherboard.UUID.ToString().ToUpper();
                    LogClientStatus($"HWID obtenido correctamente: {hwid}");
                    return hwid;
                }

                // Si no podemos obtener el HWID usando la biblioteca, crear uno alternativo
                LogClientStatus("No se pudo obtener UUID de la placa base, usando ID alternativo");
                return GenerateAlternativeHWID();
            }
            catch (Exception ex)
            {
                LogError("Error obteniendo HWID", ex);
                return GenerateAlternativeHWID();
            }
        }

        // Método alternativo para generar un ID único para este equipo
        private string GenerateAlternativeHWID()
        {
            try
            {
                // Opción 1: Usar el ID de volumen del disco C
                string volumeId = GetVolumeId();
                if (!string.IsNullOrEmpty(volumeId))
                {
                    LogClientStatus($"Usando ID de volumen como HWID alternativo: {volumeId}");
                    return volumeId;
                }

                // Opción 2: Usar dirección MAC como alternativa
                string macAddress = GetMacAddress();
                if (!string.IsNullOrEmpty(macAddress))
                {
                    LogClientStatus($"Usando dirección MAC como HWID alternativo: {macAddress}");
                    return macAddress;
                }

                // Opción 3: Usar nombre de máquina + fecha de instalación de Windows
                string computerName = Environment.MachineName;
                string installDate = GetWindowsInstallDate();
                string combined = $"{computerName}-{installDate}";

                LogClientStatus($"Usando ID compuesto como HWID alternativo: {combined}");
                return combined;
            }
            catch (Exception ex)
            {
                LogError("Error generando HWID alternativo", ex);

                // Como último recurso, generar un ID aleatorio
                string randomId = Guid.NewGuid().ToString().ToUpper();
                LogClientStatus($"Usando ID aleatorio como HWID alternativo: {randomId}");
                return randomId;
            }
        }

        // Obtener ID de volumen del disco C
        private string GetVolumeId()
        {
            try
            {
                using (Process process = new Process())
                {
                    process.StartInfo.FileName = "cmd.exe";
                    process.StartInfo.Arguments = "/c vol C:";
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.CreateNoWindow = true;

                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    // Buscar el número de serie del volumen
                    int index = output.IndexOf("es") + 2;
                    if (index > 2 && index < output.Length)
                    {
                        string volumeId = output.Substring(index).Trim();
                        return volumeId.Replace("-", "");
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Error obteniendo ID de volumen", ex);
            }

            return string.Empty;
        }

        // Obtener dirección MAC
        private string GetMacAddress()
        {
            try
            {
                NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
                foreach (NetworkInterface adapter in nics)
                {
                    // Solo usar adaptadores físicos activos
                    if (
                        adapter.OperationalStatus == OperationalStatus.Up
                        && (
                            adapter.NetworkInterfaceType == NetworkInterfaceType.Ethernet
                            || adapter.NetworkInterfaceType == NetworkInterfaceType.Wireless80211
                        )
                    )
                    {
                        PhysicalAddress address = adapter.GetPhysicalAddress();
                        if (address != null)
                        {
                            byte[] bytes = address.GetAddressBytes();
                            if (bytes != null && bytes.Length > 0)
                            {
                                return BitConverter.ToString(bytes).Replace("-", "");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Error obteniendo dirección MAC", ex);
            }

            return string.Empty;
        }

        // Obtener fecha de instalación de Windows
        private string GetWindowsInstallDate()
        {
            try
            {
                using (
                    RegistryKey key = Registry.LocalMachine.OpenSubKey(
                        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                    )
                )
                {
                    if (key != null)
                    {
                        object value = key.GetValue("InstallDate");
                        if (value != null)
                        {
                            return value.ToString();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Error obteniendo fecha de instalación de Windows", ex);
            }

            return DateTime.Now.Ticks.ToString();
        }

        private void StopTimers()
        {
            if (timer1 != null)
                timer1.Stop();
            if (timer2 != null)
                timer2.Stop();
            if (heartbeatTimer != null)
                heartbeatTimer.Stop();
        }

        public static void ExisteClaveRegistro()
        {
            // Abre la clave sin crearla
            using (RegistryKey clave = Registry.CurrentUser.OpenSubKey("Software", true))
            {
                if (clave != null)
                {
                    try
                    {
                        clave.DeleteSubKeyTree("LatinoFPS");
                    }
                    catch (System.Exception) { }
                }
            }
        }

        private List<string> InitializeBlacklistedProcesses()
        {
            return new List<string>
            {
                "RazerAppEngine",
                "MACRO COSZ 2024",
                "Tempfilenam",
                "Razer Synapse",
                "RzSynapse",
                "lghub",
                "logitechg_discord",
                "LCore",
                "SteelSeriesEngine3",
                "SteelSeriesGG",
                "XMouseButtonControl",
                "MacroRecorder",
                "AutoHotkey",
                "Redragon",
                "RedragonGamingMouse",
                "GloriousCore",
                "Roccat_Swarm",
                "rzmntr",
                "RazerCortex",
                "ggtray",
                "Bloody6",
                "Bloody",
                "Bloody5",
                "M711Software",
                "RoccatMonitor",
                "AutoHotkeyU64",
                "AutoHotkeyU32",
                "MacroCreator",
                "Keyran",
                "reWASD",
                "reWASDTray",
                "reWASDAgent",
                "tgm",
                "tgm_macro",
                "LightKeeper",
                "cmportal",
                "cm_sw",
                "HyperX NGENUITY",
                "HyperXNgenuity",
                "ZowieMouse",
                "BenQZowie",
                "XPGPrime",
                "HavitGamingMouse",
                "uRageGamingSoftware",
                "SpeedlinkMouseEditor",
                "MARVO_M618",
                "FantechMouseSoftware",
                "DeluxMouseSetting",
                "CougarUIxSystem",
                "CougarFusion",
                "T-DaggerMacroSoftware",
                "T-DaggerMouse",
                "AulaMouseMacro",
                "AulaSoftware",
                "OnikumaMouse",
                "OnikumaControl",
                "NubwoMacroEditor",
                "DragonwarGamingMouse",
                "ZeusMouseMacro",
                "ZeusEditor",
                "MachinatorMouseTool",
                "MeetionMouseSoftware",
                "AutoIt3",
                "ClickMachine",
                "MouseClicker",
                "MouseMacro",
                "SpeedMouse",
                "FastClicker",
                "RapidClick",
                "BotMice",
                "ClickBot",
                "GhostMouse",
                "MouseRecorderPro",
                "GS_AutoClicker",
                "FreeMacroPlayer",
                "MacroExpress",
                "PerfectMacro",
                "ClickerPlus",
                "EasyMacroTool",
                "QuickMacro",
                "InputAutomationTool",
                "ClickAssistant",
                "AutoClickTyper",
                "M808",
                "M908",
                "M990",
                "Attack_SharkX3Mouse",
                "NordVPN",
                "NordVPNService",
                "NordVPN.NetworkStack",
                "NordVPN.CyberSec",
                "ExpressVPN",
                "ExpressVPNService",
                "ExpressVPNUpdateService",
                "ProtonVPN",
                "ProtonVPNService",
                "vpnui",
                "vpnagent",
                "vpnservice",
                "WireGuard",
                "wg",
                "wireguard",
                "Surfshark",
                "Surfshark.Service",
                "Surfshark.UpdateService",
                "CyberGhostVPN",
                "CyberGhostService",
                "Mullvad VPN",
                "mullvad-daemon",
                "mullvad-ui",
                //Administradores de Procesos y Análisis del Sistema
                "ProcessHacker",
                "procexp",
                //"Taskmgr",
                "perfmon",
                "procexp64",
                "procexp32",
                "anvir",
                "securitytaskmanager",
                "systemexplorer",
                "prio",
                "winspy",
                "daphne",
                "taskcoach",
                "taskmanagerdeluxe",
                "taskmgrpro",
                "processlasso",
                "procmon",
                "procmon64",
                "procmon32",
                "whatishang",
                "whoslock",
                "openhandles",
                "handle",
                "handles",
                "sysinternals",
                "taskmanagerspynet",
                "taskexplorer",
                "autoruns",
                "autorunsc",
                "taskmanagerplus",
                "tasksmanager",
                //Depuradores y Desensambladores
                "ollydbg",
                "ollydbg64",
                "x64dbg",
                "x32dbg",
                "windbg",
                "gdb",
                "idag",
                "idag64",
                "idaq",
                "idaq64",
                "ida",
                "ida64",
                "radare2",
                "dnspy",
                "cheatengine",
                "cheatengine-x86_64",
                "reclass",
                "reclass64",
                "de4dot",
                // Inyectores de DLL y Herramientas de Modificación de Memoria
                "extremeinjector",
                "processinjector",
                "xenos64",
                "xenos",
                "dllinjector",
                "injector",
                "threadhijacker",
                "hijackthis",
                "blackbone",
                "winject",
                "remoteinjector",
                "apcinject",
                "kprocesshacker",
                "phlib",
                "freeinjector",
                //Editores de Código y Herramientas de Ingeniería Inversa
                "notepad++",
                "hexeditor",
                "winhex",
                "hxd",
                "010editor",
                "immunitydebugger",
                "peid",
                "peexplorer",
                "c32asm",
                "ollyice",
                //Escáneres y Herramientas de Análisis de Malware
                "tcpview",
                "wireshark",
                "snifferspy",
                "networkspy",
                "networkminer",
                "netscan",
                "smartsniff",
                "smartwhois",
                //Emuladores y Sandboxes
                "sandboxiedcomlaunch",
                "sandboxierpcss",
                //"vmware",
                //"vmtoolsd",
                //"vmwaretray",
                //"vmwareuser",
                "vboxservice",
                "vboxtray",
                "qemu-system",
                "wine",
                "fiddler",
                "mitmproxy",
                "burpsuite",
                "proxycap",
                "proxifier",
                "proxytunnel",
                "charlesproxy",
                "tor",
                "torbrowser",
                "vidalia",
                "privoxy",
                "squid",
                "hydra",
                "medusa",
                "ncrack",
                "john",
                "hashcat",
                "crunch",
                "aircrack-ng",
                "reaver",
                "wifite",
                "sqlmap",
                "sqlninja",
                "metasploit",
                "msfconsole",
                "msfvenom",
                "beef",
                "ares",
                "cobaltstrike",
                "bruteforce",
                "hashkiller",
                "unpacker",
                "de4dot",
                "upx",
                "armadillo",
                "vmprotect",
                "themida",
                "xnosnoop",
                "dumper",
                "hxdump",
                "cracker",
                "keygen",
                "patcher",
                "regmon",
                "sniffpass",
                "productkey",
                "serialbox",
                "winspy",
                "perfectkeylogger",
                "actualspy",
                "refog",
                "bestkeylogger",
                "spytech",
                "spystorm",
                "realtime-spy",
                "shadowkeylogger",
                "monitoringsoftware",
                "wiredkeys",
                "stalker",
                "sniper-spy",
                "systeminfo",
                "processmonitor",
                "taskanalysis",
                "taskmanagerplus64",
                "advancedtaskmanager",
                "securityexplorer",
                "sysanalyzer",
                "processxray",
                "taskinspector",
                "taskkiller",
                "winprocessmanager",
                "procview",
                "prcsview",
                "taskfreezer",
                "hiddenprocess",
                "processrevealer",
                "prockill",
                "taskguard",
                "taskviewer",
                "sysinspector",
                "kerneltrace",
                "winspyplus",
                "debugger64",
                "debugger32",
                "debugme",
                "trapflag",
                "breakpointchecker",
                "stacktrace",
                "opcodeviewer",
                "dissasemblerpro",
                "codeinspector",
                "opcodeanalyzer",
                "fastdebugger",
                "ptrace",
                "decompiler",
                "asmdebug",
                "codehunter",
                "memanalyst",
                "softice",
                "comtrace",
                "reveng",
                "hwbpmonitor",
                "bytecodeviewer",
                "injectplus",
                "dllhijacker",
                "memhijacker",
                "dllsnoop",
                "libinjector",
                "hijackdll",
                "remotecode",
                "processsyringe",
                "dynamicinjector",
                "apcspy",
                "hookdetect",
                "detours",
                "codepatcher",
                "memmod",
                "cheatdev",
                "memhackpro",
                "stealthinjector",
                "dllmodder",
                "patchinj",
                "dumperx",
                "binaryeditor",
                "hexworkshop",
                "biteshift",
                "bytepatcher",
                "memview",
                "memscan",
                "binanalyzer",
                "memscraper",
                "patternscanner",
                "memorypro",
                "hexdec",
                "ramreader",
                "fastedit",
                "tracehex",
                "xorviewer",
                "bitmaskedit",
                "fuzzeditor",
                "ramtracer",
                "payloadeditor",
                "procscanner",
                "netanalyzer",
                "packetspy",
                "sniffingtool",
                "tcpdump",
                "netpeek",
                "spyproxy",
                "packetrace",
                "rawsockets",
                "netwatch",
                "netmonitorplus",
                "iptracer",
                "dnslookup",
                "netrecon",
                "packetstorm",
                "networkwatchdog",
                "packetsnifferpro",
                "lanmonitor",
                "wifisniffer",
                "firewallbypass",
                "pktcapture",
                "bochs",
                "xenctrl",
                "guesttools",
                "parallelsvm",
                "dockerdaemon",
                "wineserver",
                "winecfg",
                "sandboxutility",
                "emuhost",
                "testcontainer",
                "qemuwrapper",
                "cloudhost",
                "vmsecurity",
                "hypervclient",
                "virtmon",
                "vboxguest",
                "bluepill",
                "hvmloader",
                "kvmservice",
                "shadowvm",
                "stealthproxy",
                "anonvpn",
                "dnsbypass",
                "vpnsecure",
                "proxyhunter",
                "torproxy",
                "hiddenweb",
                "relaystation",
                "tunnelblick",
                "openvpn",
                "vpncontrol",
                "sockscap",
                "proxytool",
                "privatesocks",
                "browserspoofer",
                "mitmsuite",
                "networkstealth",
                "webcamblocker",
                "hostmanip",
                "ipspoof",
                "hashdecrypt",
                "exploitscanner",
                "hackingtool",
                "reverseproxy",
                "webscanner",
                "bruteforceattack",
                "pwnsuite",
                "securitybypass",
                "sqlscanner",
                "cfrtools",
                "shellgen",
                "wafbypass",
                "exploitbuilder",
                "vulnscanner",
                "pwnhub",
                "sqlihunter",
                "portstealer",
                "sessionstealer",
                "authbypass",
                "securityhacker",
                "keyfinder",
                "licensebypass",
                "serialhunter",
                "unlocker",
                "registryunlock",
                "keymaker",
                "trialreset",
                "cracked",
                "patcherpro",
                "serialseeker",
                "activationtool",
                "hwidspoof",
                "fakekeygen",
                "bypasslicense",
                "passwordstealer",
                "productkeyfinder",
                "licensekeygen",
                "serialbruteforce",
                "activator",
                "licensepatch",
                "ratserver",
                "backdoor",
                "spyagent",
                "keycapture",
                "keystrokeviewer",
                "activitylogger",
                "spyrat",
                "remoteadmin",
                "stealthkeylogger",
                "keyspy",
                "systemmonitor",
                "rootkit",
                "monitoringtool",
                "silentlogger",
                "wiretapper",
                "camspy",
                "passwordlogger",
                "invisiblekeylogger",
                "stealthmonitor",
                "spyrecorder",
                "razerCentralService",
                "razer synapse service",
                "razer synapse service process",
                "razer synapse service 3",
                "razer central",


            };
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            try
            {
                InitializeApplication();
            }
            catch (Exception ex)
            {
                LogError("Error during initialization", ex);
                ShowAndExit(
                    $"Error during startup. Please check your installation. {ex}",
                    "alert",
                    10000
                );
            }
        }

        private async void InitializeApplication()
        {
            if (!VerifyDependencies())
                return;
            LoadConfiguration();
            StartNamedPipeServer();
            InitializeClient();
            InitializeTimers();
            this.ShowInTaskbar = false;
            LoadingBar.Width = 0;
            await ConnectToServerAsync();
        }

        private bool VerifyDependencies()
        {
            string[] requiredFiles = new[]
            {
                "ext11c.dll",
                "Newtonsoft.Json.dll",
                "SuperSimpleTcp.dll",
            };
            foreach (string file in requiredFiles)
            {
                if (!File.Exists(Path.Combine(pach, file)))
                {
                    ShowAndExit($"Failed to load '{file}'", "alert", 10000);
                    return false;
                }
            }
            return true;
        }

        private void LoadConfiguration()
        {
            try
            {
                // Verificar que el archivo existe
                string configPath = Path.Combine(pach, "ext11c.dll");
                if (!File.Exists(configPath))
                {
                    string errorMsg =
                        $"Archivo de configuración 'ext11c.dll' no encontrado en: {configPath}";
                    LogError(errorMsg, new Exception("Archivo no encontrado"));
                    ShowAndExit(errorMsg, "Error de Configuración", 10000);
                    return;
                }

                // Intentar cargar la configuración
                INIFile tx = new INIFile(configPath);

                // Leer y verificar que cada valor exista
                game = tx.IniReadValue("CONFIG", "GAME");
                if (string.IsNullOrEmpty(game))
                {
                    LogError(
                        "Valor 'GAME' no encontrado o vacío en la configuración",
                        new Exception("Valor de configuración faltante")
                    );
                }

                serverIp = tx.IniReadValue("CONFIG", "IP");
                if (string.IsNullOrEmpty(serverIp))
                {
                    LogError(
                        "Valor 'IP' no encontrado o vacío en la configuración",
                        new Exception("Valor de configuración faltante")
                    );
                }

                string portStr = tx.IniReadValue("CONFIG", "PORT");
                if (string.IsNullOrEmpty(portStr) || !int.TryParse(portStr, out port))
                {
                    LogError(
                        "Valor 'PORT' no encontrado, vacío o no es un número válido",
                        new Exception("Valor de configuración inválido")
                    );
                }

                keyrecep = tx.IniReadValue("CONFIG", "KEY");
                if (string.IsNullOrEmpty(keyrecep))
                {
                    LogError(
                        "Valor 'KEY' no encontrado o vacío en la configuración",
                        new Exception("Valor de configuración faltante")
                    );
                }

                // Registrar valores para depuración (excluyendo la clave por seguridad)
                //LogClientStatus($"Configuración cargada - Juego: {game}, IP: {serverIp}, Puerto: {port}");
            }
            catch (Exception ex)
            {
                LogError($"Error loading configuration", ex);
                ShowAndExit(
                    $"Error loading configuration: {ex.Message}",
                    "Error de Configuración",
                    10000
                );
            }
        }

        private void InitializeClient()
        {
            try
            {
                client = new SimpleTcpClient(serverIp, port);
                client.Events.Connected += Events_Connected;
                client.Events.DataReceived += Events_DataReceived;
                client.Events.Disconnected += Events_Disconnected;
                LogClientStatus("Cliente TCP inicializado correctamente");
            }
            catch (Exception ex)
            {
                LogError("Error al inicializar el cliente TCP", ex);
                client = null; // Asegurarse de que client sea null en caso de error
            }
        }

        private bool ConnectWithRetries(int timeoutMs, int maxRetries = 5) // Aumentar de 3 a 5
        {
            if (client == null)
            {
                LogError("Error de conexión", new Exception("Cliente TCP no inicializado"));
                return false;
            }

            int retryCount = 0;
            while (retryCount < maxRetries)
            {
                try
                {
                    LogClientStatus($"Intento de conexión {retryCount + 1}/{maxRetries}");
                    client.Connect();

                    // Aumentar el tiempo de espera para verificar la estabilidad de la conexión
                    System.Threading.Thread.Sleep(2000); // Esperar 2 segundos

                    if (client.IsConnected)
                    {
                        LogClientStatus("Conexión estable después de 2 segundos");
                        return true;
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error en intento de conexión {retryCount + 1}", ex);
                }

                retryCount++;
                System.Threading.Thread.Sleep(2000); // Aumentar de 1 a 2 segundos entre reintentos
            }

            LogClientStatus($"Fallaron todos los {maxRetries} intentos de conexión");
            return false;
        }

        // Reemplaza el método ConnectToServerAsync actual con este:
        // Modificar el método ConnectToServerAsync para esperar la respuesta de autenticación
        private async Task ConnectToServerAsync()
        {
            await Task.Run(() =>
            {
                try
                {
                    // Verificación del cliente existente
                    if (client == null)
                    {
                        throw new Exception("Cliente TCP no inicializado");
                    }

                    bool connected = ConnectWithRetries(10000);

                    if (connected && client.IsConnected)
                    {
                        // Enviar autenticación
                        var authRequest = new
                        {
                            action = "AUTH",
                            key = keyrecep,
                            hwid = getHwid(),
                        };

                        LogClientStatus("Enviando solicitud de autenticación...");
                        client.Send(JsonConvert.SerializeObject(authRequest));

                        // Añadir una pausa para dar tiempo a recibir la respuesta
                        System.Threading.Thread.Sleep(1000);

                        // Verificar nuevamente que seguimos conectados antes de continuar
                        if (!client.IsConnected)
                        {
                            throw new Exception(
                                "La conexión se perdió después de la autenticación"
                            );
                        }

                        LogClientStatus(
                            "Verificación de conexión después de autenticación: Conectado"
                        );
                    }
                    else
                    {
                        throw new Exception("La conexión falló después de varios intentos");
                    }
                }
                catch (Exception ex)
                {
                    LogError("Initial connection failed", ex);
                    this.Invoke(
                        (MethodInvoker)
                            delegate
                            {
                                string errorMsg = "Failed to connect to server. Possible causes:\n";
                                errorMsg += "- Check your internet connection\n";
                                errorMsg += "- Firewall may be blocking the connection\n";
                                errorMsg += "- Server may be temporarily unavailable\n";
                                errorMsg += $"\nTechnical details: {ex.Message}";

                                ShowAndExit(errorMsg, "Connection Error", 8000);
                            }
                    );
                }
            });
        }

        private void StartGame()
        {
            gameStartInfo.FileName = $"{game}.exe";
            gameStartInfo.Arguments = $"{arguments[0]} {arguments[1]}";
            gameStartInfo.WorkingDirectory = pach.Replace("\\HackShield", "\\");
            gameStartInfo.ErrorDialog = true;

            try
            {
                Process.Start(gameStartInfo);
                //isGameRunning = true;
            }
            catch (Exception ex)
            {
                LogError("Game start error", ex);
                ShowAndExit("Failed to start game", "alert", 10000);
            }
        }

        private async Task DetectCheatProcessesAsync()
        {
            try
            {
                Process[] processes = Process.GetProcesses();
                foreach (Process process in processes)
                {
                    if (blacklistedProcesses.Contains(process.ProcessName))
                    {
                        await HandleCheatDetectionAsync(process);
                        return;
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Cheat detection error", ex);
            }
        }

        private async Task HandleCheatDetectionAsync(Process cheatProcess)
        {
            StopTimers();
            await KillGameProcessesAsync();
            ShowDetectionUI(cheatProcess.ProcessName);
            await SendDetectionToServerAsync(cheatProcess.ProcessName);
            ShowAndExit($"Game terminated due to illegal program {cheatProcess.ProcessName} detection", "alert", 10000);
        }

        private async Task ReportThreatAsync(string processName)
        {
            await Task.Run(() =>
            {
                string jsonData = JsonConvert.SerializeObject(
                    new
                    {
                        action = "THREAT",
                        message = processName,
                        user_id = arguments.Length > 0 ? arguments[0] : null,
                    }
                );
                client.Send(jsonData);
            });
        }

        private async Task KillGameProcessesAsync()
        {
            await Task.WhenAll(KillProcessAsync("PointBlank"));
        }

        private async Task KillProcessAsync(string processName)
        {
            await Task.Run(() =>
            {
                try
                {
                    Process[] processes = Process.GetProcessesByName(processName);
                    foreach (Process process in processes)
                    {
                        process.Kill();
                        process.WaitForExit(10000); // Espera hasta 5 segundos
                    }
                }
                catch (Exception ex)
                {
                    LogError($"Error killing process {processName}", ex);
                }
            });
        }

        private void ShowDetectionUI(string detectedProcess)
        {
            this.Show();
            this.BackgroundImage = Resources.detected;
            LoadingBar.Hide();
        }

        private void ReportThreat(string thread)
        {
            try
            {
                if (client.IsConnected)
                {
                    string jsonData = JsonConvert.SerializeObject(
                        new
                        {
                            action = "THREAT",
                            message = thread,
                            user_id = arguments.Length > 0 ? arguments[0] : null,
                        }
                    );
                    client.Send(jsonData);
                }
            }
            catch (Exception ex)
            {
                LogError("Error reporting threat", ex);
            }
        }

        private async Task SendDetectionToServerAsync(string detectedProcess)
        {
            if (client.IsConnected)
            {
                string jsonData = JsonConvert.SerializeObject(
                    new
                    {
                        action = "CHEAT_REPORT",
                        process = detectedProcess,
                        user_id = arguments.Length > 0 ? arguments[0] : null,
                    }
                );

                await SendToServerAsync(jsonData);
            }
        }

        private async Task SendToServerAsync(string message)
        {
            await Task.Run(() =>
            {
                try
                {
                    client.Send(message);
                }
                catch (Exception ex)
                {
                    LogError("Error sending message to server", ex);
                }
            });
        }

        private void Events_Connected(object sender, SuperSimpleTcp.ConnectionEventArgs e)
        {
            this.Invoke(
                (MethodInvoker)
                    delegate
                    {
                        try
                        {
                            LogClientStatus("Connected to server");

                            // Esperar un momento antes de iniciar timers o enviar datos
                            // Esto ayuda a evitar problemas de temporización
                            System.Threading.Thread.Sleep(500);

                            if (client.IsConnected)
                            {
                                LogClientStatus("Conexión estable después de 500ms");
                                if (timer1 != null)
                                    timer1.Start();
                            }
                            else
                            {
                                LogClientStatus(
                                    "La conexión se perdió inmediatamente después de conectar"
                                );
                            }
                        }
                        catch (Exception ex)
                        {
                            LogError("Error in connection event handler", ex);
                        }
                    }
            );
        }

        private void Events_DataReceived(object sender, SuperSimpleTcp.DataReceivedEventArgs e)
        {
            this.Invoke(
                (MethodInvoker)
                    async delegate
                    {
                        try
                        {
                            byte[] rawData = e
                                .Data.Array.Skip(e.Data.Offset)
                                .Take(e.Data.Count)
                                .ToArray();
                            string receivedData = Encoding.UTF8.GetString(
                                e.Data.Array,
                                e.Data.Offset,
                                e.Data.Count
                            );
                            dynamic response = JsonConvert.DeserializeObject(receivedData);
                            if (response.action == "AUTH_RESPONSE")
                            {
                                if (response.status == "success")
                                {
                                    LogClientStatus("AUTH_RESPONSE OK");
                                }
                                else
                                {
                                    client.Disconnect();
                                }
                            }
                            await HandleServerCommandAsync(rawData);
                        }
                        catch (Exception ex)
                        {
                            LogError("Error processing server command", ex);
                        }
                    }
            );
        }

        private void Events_Disconnected(object sender, SuperSimpleTcp.ConnectionEventArgs e)
        {
            this.Invoke(
                (MethodInvoker)
                    async delegate
                    {
                        try
                        {
                            LogClientStatus("Disconnected from server");
                            StopTimers();
                            await KillGameProcessesAsync();
                        }
                        catch (Exception ex)
                        {
                            LogError("Error in disconnection event handler", ex);
                            Application.Exit();
                        }
                    }
            );
        }

        private async Task HandleServerCommandAsync(byte[] data)
        {
            string jsonData = Encoding.UTF8.GetString(data);
            dynamic obj = JsonConvert.DeserializeObject(jsonData);
            string action = obj.action;
            string key = obj.key;

            switch (action)
            {
                case "disconnect":
                    await HandleGameTermination();
                    break;
                case "shutdown":
                    await ExecuteShutdownCommand();
                    break;
                case "streamviewer":
                    await StartStreamViewer(obj);
                    break;
            }
        }

        private async Task StartStreamViewer(dynamic obj)
        {
            string executable = obj.executable;
            string ip = obj.ip;
            string port = obj.port;
            string postData;

            await Task.Run(() =>
            {
                try
                {
                    // Configura el proceso
                    var process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = executable,
                            Arguments = $"{ip} {port}",
                            UseShellExecute = false,
                            RedirectStandardOutput = false,
                            CreateNoWindow = false,
                        },
                        EnableRaisingEvents = true, // Necesario para el evento Exited
                    };

                    // Evento que se dispara cuando el proceso termina
                    process.Exited += (sender, e) =>
                    {
                        //Console.WriteLine($"🛑 Proceso terminado (Código: {process.ExitCode})");
                        if (client.IsConnected)
                        {
                            postData = JsonConvert.SerializeObject(
                                new
                                {
                                    action = "STREAMVIEWER",
                                    message = "Process terminated",
                                    user_id = arguments.Length > 0 ? arguments[0] : null,
                                }
                            );

                            client.Send(postData);
                        }
                        //process.Dispose(); // Liberar recursos
                    };

                    // Intenta iniciar el proceso
                    bool started = process.Start();

                    if (!started)
                    {
                        if (client.IsConnected)
                        {
                            postData = JsonConvert.SerializeObject(
                                new
                                {
                                    action = "STREAMVIEWER",
                                    message = "Failed to start process",
                                    user_id = arguments.Length > 0 ? arguments[0] : null,
                                }
                            );
                            client.Send(postData);
                        }
                        //Console.WriteLine("❌ Error: No se pudo iniciar el proceso.");
                        //process.Dispose();
                    }

                    if (client.IsConnected)
                    {
                        postData = JsonConvert.SerializeObject(
                            new
                            {
                                action = "STREAMVIEWER",
                                message = "Process started successfully",
                                user_id = arguments.Length > 0 ? arguments[0] : null,
                            }
                        );
                        client.Send(postData);
                    }
                }
                catch (Exception ex)
                {
                    if (client.IsConnected)
                    {
                        postData = JsonConvert.SerializeObject(
                            new
                            {
                                action = "STREAMVIEWER",
                                message = $"Error: {ex.Message}",
                                user_id = arguments.Length > 0 ? arguments[0] : null,
                            }
                        );
                        client.Send(postData);
                    }
                }
            });
        }

        private async Task ExecuteShutdownCommand()
        {
            await Task.Run(() =>
            {
                ProcessStartInfo shutdownInfo = new ProcessStartInfo
                {
                    FileName = "cmd",
                    Arguments = "/c shutdown -p",
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                };

                try
                {
                    Process.Start("shutdown / s / t 1");
                    //Process.Start(shutdownInfo);
                }
                catch (Exception ex)
                {
                    LogError("Shutdown command failed", ex);
                    Application.Exit();
                }
            });
        }

        public static void ShowAndExit(
            string message,
            string title,
            int durationMilliseconds = 3000
        )
        {
            Form msgForm = new Form()
            {
                Width = 300,
                Height = 150,
                StartPosition = FormStartPosition.CenterScreen,
                FormBorderStyle = FormBorderStyle.FixedDialog,
                ControlBox = false,
                Text = title,
                TopMost = true,
            };

            Label lbl = new Label()
            {
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                Font = new Font("Segoe UI", 12),
                Text = message,
            };

            msgForm.Controls.Add(lbl);

            Timer timer = new Timer();
            timer.Interval = durationMilliseconds;
            timer.Tick += (s, e) =>
            {
                timer.Stop();
                msgForm.Close();
                Application.Exit(); // Salida automática de la app
            };

            timer.Start();
            msgForm.ShowDialog();
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            UpdateLoadingProgress();
            if (loadingProgress >= 6)
            {
                ExisteClaveRegistro();
                timer1.Stop();
                this.Hide();
                StartInfoClient();
                timer2.Start();
                heartbeatTimer.Start(); // Iniciar el timer de heartbeat
            }
        }

        private async void timer2_Tick(object sender, EventArgs e)
        {
            await CheckSystemState();
        }

        private void heartbeatTimer_Tick(object sender, EventArgs e)
        {
            SendHeartbeat();
        }

        // Método para enviar el heartbeat
        private void SendHeartbeat()
        {
            try
            {
                if (client != null && client.IsConnected)
                {
                    // Enviar un mensaje simple de heartbeat
                    string heartbeatData = JsonConvert.SerializeObject(
                        new
                        {
                            action = "HEARTBEAT",
                            user_id = arguments.Length > 0 ? arguments[0] : null,
                            timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                        }
                    );

                    client.Send(heartbeatData);
                    LogClientStatus("Heartbeat enviado");
                }
                else
                {
                    LogClientStatus("No se pudo enviar heartbeat: cliente no conectado");
                    // Intentar reconectar si es necesario
                    if (client != null && !client.IsConnected)
                    {
                        LogClientStatus("Intentando reconectar debido a desconexión detectada...");
                        // Intentar reconectar
                        ConnectWithRetries(10000);
                    }
                }
            }
            catch (Exception ex)
            {
                LogError("Error enviando heartbeat", ex);
            }
        }

        private void UpdateLoadingProgress()
        {
            loadingProgress++;
            int progressPercentage = (loadingProgress * 20);

            if (progressPercentage <= 100)
            {
                UpdateLoadingBar(progressPercentage);
            }

            if (loadingProgress >= 6)
            {
                ExisteClaveRegistro();
                timer1.Stop();
                this.Hide();
                StartInfoClient();
                timer2.Start();
            }
        }

        private void StartInfoClient()
        {
            try
            {
                if (client == null)
                {
                    LogClientStatus("No se pudo enviar INIT: cliente no inicializado");
                    return;
                }

                // Verificar si estamos conectados y reconectar si es necesario
                if (!client.IsConnected)
                {
                    LogClientStatus("El cliente se desconectó. Intentando reconectar...");

                    // Intentar reconectar
                    bool reconnected = ConnectWithRetries(10000);
                    if (!reconnected || !client.IsConnected)
                    {
                        LogClientStatus("No se pudo reconectar al servidor");
                        return;
                    }

                    // Reenviar la autenticación
                    var authRequest = new
                    {
                        action = "AUTH",
                        key = keyrecep,
                        hwid = getHwid(),
                    };
                    client.Send(JsonConvert.SerializeObject(authRequest));

                    // Esperar brevemente para la autenticación
                    System.Threading.Thread.Sleep(1000);

                    if (!client.IsConnected)
                    {
                        LogClientStatus("La reconexión falló durante la autenticación");
                        return;
                    }
                }

                // Si llegamos aquí, estamos conectados y autenticados
                string postData = JsonConvert.SerializeObject(
                    new
                    {
                        action = "INIT",
                        user_id = arguments.Length > 0 ? arguments[0] : null,
                        hwid = getHwid(),
                    }
                );

                client.Send(postData);
                LogClientStatus("Mensaje INIT enviado correctamente");
            }
            catch (Exception ex)
            {
                LogError("Error starting InfoClient", ex);
            }
        }

        private void UpdateLoadingBar(int percentage)
        {
            LoadingBar.Width = (int)(percentage * LOADING_BAR_MAX_WIDTH / 100);
        }

        private async Task CheckSystemState()
        {
            await DetectCheatProcessesAsync();

            if (!await IsGameRunningAsync() || !CheckInternetConnection())
            {
                await HandleGameTermination();
            }
        }

        private async Task<bool> IsGameRunningAsync()
        {
            return await Task.Run(() =>
            {
                return Process.GetProcessesByName("PointBlank").Length > 0;
            });
        }

        private bool CheckInternetConnection()
        {
            return NetworkInterface.GetIsNetworkAvailable();
        }

        private async Task HandleGameTermination()
        {
            StopTimers();
            await KillGameProcessesAsync();
            Application.Exit();
        }

        private void LogClientStatus(string status)
        {
            string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {status}";
            Debug.WriteLine(logEntry);
            AppendToLogFile(logEntry);
        }

        private void LogError(string message, Exception ex)
        {
            string logEntry =
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] ERROR: {message}: {ex.Message}";
            Debug.WriteLine(logEntry);
            AppendToLogFile(logEntry);
        }

        private void AppendToLogFile(string logEntry)
        {
            try
            {
                using (StreamWriter writer = new StreamWriter(logFilePath, true)) // 'true' para agregar contenido sin sobrescribir
                {
                    writer.WriteLine(logEntry);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error writing to log file: {ex.Message}");
            }
        }

        private void StartNamedPipeServer()
        {
            // Evitar iniciar múltiples instancias
            if (isServerRunning)
                return;

            isServerRunning = true;
            LogClientStatus("[Pipe] Iniciando servidor de pipe...");
            new System.Threading.Thread(() =>
            {
                while (isServerRunning)
                {
                    using (
                        NamedPipeServerStream pipeServer = new NamedPipeServerStream(
                            "AntiCheatPipe",
                            PipeDirection.In,
                            1,
                            PipeTransmissionMode.Byte,
                            PipeOptions.None
                        )
                    ) // Modo síncrono para depurar
                    {
                        try
                        {
                            // Esperar conexión
                            pipeServer.WaitForConnection();

                            Invoke(
                                (MethodInvoker)(
                                    () =>
                                    {
                                        LogClientStatus("[Pipe] Cliente conectado!");
                                    }
                                )
                            );

                            // Buffer para recibir datos
                            byte[] buffer = new byte[1024];

                            // Mientras la conexión esté activa
                            while (pipeServer.IsConnected)
                            {
                                try
                                {
                                    // Leer datos (bloqueante)
                                    int bytesRead = pipeServer.Read(buffer, 0, buffer.Length);

                                    if (bytesRead > 0)
                                    {
                                        string response = System.Text.Encoding.UTF8.GetString(
                                            buffer,
                                            0,
                                            bytesRead
                                        );

                                        Invoke(
                                            (MethodInvoker)(
                                                () =>
                                                {
                                                    // Procesar el mensaje
                                                    //LogClientStatus(response);

                                                    dynamic obj = JsonConvert.DeserializeObject(
                                                        response
                                                    );

                                                    string action = obj.action;
                                                    string message = obj.message;

                                                    switch (action)
                                                    {
                                                        case "REPORT_DL":
                                                            {
                                                                if (client.IsConnected)
                                                                {
                                                                    var jsonData = new
                                                                    {
                                                                        action = action,
                                                                        message = message,
                                                                        user_id = arguments.Length
                                                                        > 0
                                                                            ? arguments[0]
                                                                            : null,
                                                                    };

                                                                    client.Send(
                                                                        JsonConvert.SerializeObject(
                                                                            jsonData
                                                                        )
                                                                    );
                                                                }
                                                            }
                                                            break;
                                                        case "INJECTION_ALERT":
                                                            {
                                                                if (client.IsConnected)
                                                                {
                                                                    var jsonData = new
                                                                    {
                                                                        action = action,
                                                                        message = message,
                                                                        user_id = arguments.Length
                                                                        > 0
                                                                            ? arguments[0]
                                                                            : null,
                                                                    };

                                                                    client.Send(
                                                                        JsonConvert.SerializeObject(
                                                                            jsonData
                                                                        )
                                                                    );
                                                                }
                                                            }
                                                            break;
                                                        default:
                                                            break;
                                                    }
                                                }
                                            )
                                        );
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }
                                catch (IOException)
                                {
                                    break;
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            Invoke(
                                (MethodInvoker)(
                                    () =>
                                    {
                                        pipeServer.Disconnect();
                                        pipeServer.Close();

                                        LogError("Error en Pipe Server", ex);
                                    }
                                )
                            );
                        }
                        // Esperar un momento antes de reiniciar
                        System.Threading.Thread.Sleep(500);
                    } // El using se asegura de que el pipe se cierre correctamente
                }
            })
            {
                IsBackground = true,
                Name = "PipeServerThread",
            }.Start();
        }
    }
}
