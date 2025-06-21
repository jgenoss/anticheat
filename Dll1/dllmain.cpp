// dllmain.cpp restructurado
#include "pch.h"
#include <windows.h>
#include <wininet.h>
#include <iostream>
#include <vector>
#include <chrono>
#include <cmath>
#include <numeric>
#include <tlhelp32.h>
#include <string>
#include <thread>
#include <codecvt>
#include <fstream>
#include <mutex>
#include <Psapi.h>
#include <shlwapi.h>
#include <winternl.h>
#include <shellapi.h>
#include "detours.h"
#include <nlohmann/json.hpp>
#include "EncryptionLib.h"
#include "FileProtection.h"
#include <wintrust.h>
#include <softpub.h>
#include <algorithm>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

using json = nlohmann::json;

//----------------------------------------------------------------------
// CONSTANTES Y DEFINICIONES
//----------------------------------------------------------------------

#define PIPE_NAME "\\\\.\\pipe\\AntiCheatPipe"
#define SERVICE_NAME L"ServicioMonitor"

//GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

const std::wstring ENCRYPTED_CONFIG_PATH = L"protected_files.dat";
const std::wstring CONFIG_KEY_PATH = L"clave.key";

// Tipos personalizados
typedef BOOL(WINAPI* SetProcessMitigationPolicyFunc)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
typedef int(__stdcall* MSGBOXAAPI)(IN HWND hWnd, IN LPCSTR lpText, IN LPCSTR lpCaption, IN UINT uType, IN WORD wLanguageId, IN DWORD dwMilliseconds);

//----------------------------------------------------------------------
// VARIABLES GLOBALES
//----------------------------------------------------------------------

// Hilos y handles
std::thread Thread;
HWND windowHandle;
DWORD processId;
std::mutex mtx;
std::atomic<bool> stopThread(false);
std::thread monitoringThread;
HHOOK mouseHook = NULL;
HANDLE hPipe = INVALID_HANDLE_VALUE;

// Estado de la aplicación
bool isProcessingSuspension = false;
const char* windowTitle = "Point Blank";

// Objetos para funcionalidad principal
EncryptionLib encryption;
FileProtection fileProtection;
MSGBOXAAPI MessageBoxTimeoutA;




//----------------------------------------------------------------------
// CONSTANTES MEJORADAS PARA DETECCIÓN DE MACROS
//----------------------------------------------------------------------

// Configuración más realista basada en investigación
const size_t HISTORY_SIZE = 50;              // Aumentado para mejor análisis estadístico
const size_t MIN_SAMPLE_SIZE = 15;           // Mínimo de clics para análisis confiable
const double MIN_HUMAN_INTERVAL_MS = 50.0;   // Límite físico humano más realista
const double MAX_HUMAN_INTERVAL_MS = 2000.0; // Máximo razonable para gaming
const double VARIANCE_THRESHOLD_LOW = 25.0;  // Para detección de patrones muy regulares
const double VARIANCE_THRESHOLD_HIGH = 100.0; // Para rangos sospechosos
const double COEFFICIENT_VARIATION_THRESHOLD = 0.08; // CV muy bajo indica automatización
const double AUTOCORRELATION_THRESHOLD = 0.75; // Correlación alta indica patrones repetitivos

// Sistema de puntuación graduada
const int SUSPICION_THRESHOLD = 75;          // Umbral para advertencia
const int CRITICAL_THRESHOLD = 90;           // Umbral para acción

// Estructura mejorada para tracking de clics
struct AdvancedClickData {
    POINT position;
    std::chrono::high_resolution_clock::time_point timestamp;
    double timeDiff;        // Tiempo desde el clic anterior
    double movementSpeed;   // Velocidad del movimiento del mouse
    bool wasMoving;         // Si el mouse se estaba moviendo
};

// Variables globales mejoradas
std::vector<AdvancedClickData> advancedClickHistory;
std::vector<double> baselineTimings;         // Para calibración individual
double userBaselineVariance = 50.0;         // Varianza baseline del usuario
int suspicionScore = 0;                      // Puntuación acumulativa
bool isCalibrating = true;                   // Período de calibración inicial
std::chrono::steady_clock::time_point calibrationStart;
int legitClicksCount = 0;

//----------------------------------------------------------------------
// FUNCIONES DE ANÁLISIS ESTADÍSTICO AVANZADO
//----------------------------------------------------------------------

// Calcula el coeficiente de variación
double CalculateCoefficientOfVariation(const std::vector<double>& values) {
    if (values.size() < 2) return 0.0;

    double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    if (mean == 0.0) return 0.0;

    double variance = 0.0;
    for (double val : values) {
        variance += (val - mean) * (val - mean);
    }
    variance /= (values.size() - 1);

    double stdDev = sqrt(variance);
    return stdDev / mean;
}

// Calcula la autocorrelación lag-1
double CalculateAutocorrelation(const std::vector<double>& values) {
    if (values.size() < 10) return 0.0;

    double mean = std::accumulate(values.begin(), values.end(), 0.0) / values.size();
    double numerator = 0.0, denominator = 0.0;

    for (size_t i = 0; i < values.size() - 1; i++) {
        numerator += (values[i] - mean) * (values[i + 1] - mean);
    }

    for (size_t i = 0; i < values.size(); i++) {
        denominator += (values[i] - mean) * (values[i] - mean);
    }

    return denominator > 0 ? numerator / denominator : 0.0;
}

// Detecta patrones fijos/periódicos
bool DetectFixedPatterns(const std::vector<double>& timings) {
    if (timings.size() < 20) return false;

    // Buscar patrones repetitivos exactos
    std::map<int, int> intervalCounts;
    for (double timing : timings) {
        int roundedTiming = static_cast<int>(timing + 0.5);
        intervalCounts[roundedTiming]++;
    }

    // Si más del 70% de los clics tienen el mismo timing (±2ms), es sospechoso
    for (const auto& pair : intervalCounts) {
        if (pair.second > timings.size() * 0.7) {
            return true;
        }
    }

    return false;
}

// Análisis de entropía Shannon
double CalculateEntropy(const std::vector<double>& timings) {
    if (timings.size() < 10) return 10.0; // Valor alto por defecto

    // Discretizar los timings en bins de 5ms
    std::map<int, int> bins;
    for (double timing : timings) {
        int bin = static_cast<int>(timing / 5.0);
        bins[bin]++;
    }

    double entropy = 0.0;
    double total = static_cast<double>(timings.size());

    for (const auto& pair : bins) {
        double probability = pair.second / total;
        if (probability > 0) {
            entropy -= probability * log2(probability);
        }
    }

    return entropy;
}

//----------------------------------------------------------------------
// SISTEMA DE CALIBRACIÓN INDIVIDUAL
//----------------------------------------------------------------------

void UpdateUserBaseline(const std::vector<double>& timings) {
    if (timings.size() < 30) return;

    // Calcular estadísticas baseline del usuario
    double mean = std::accumulate(timings.begin(), timings.end(), 0.0) / timings.size();
    double variance = 0.0;

    for (double timing : timings) {
        variance += (timing - mean) * (timing - mean);
    }
    variance /= (timings.size() - 1);

    // Actualizar baseline con suavizado exponencial
    userBaselineVariance = userBaselineVariance * 0.8 + variance * 0.2;

    // Guardar para referencia futura
    baselineTimings = timings;
}

bool IsInCalibrationPeriod() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - calibrationStart).count();
    return elapsed < 10 && legitClicksCount < 200; // 10 minutos o 200 clics legítimos
}

//----------------------------------------------------------------------
// DETECCIÓN DE MOVIMIENTO DEL MOUSE
//----------------------------------------------------------------------

double CalculateMovementSpeed(const POINT& p1, const POINT& p2, double timeDiff) {
    if (timeDiff <= 0) return 0.0;

    double distance = sqrt(pow(p2.x - p1.x, 2) + pow(p2.y - p1.y, 2));
    return distance / timeDiff; // pixels por millisegundo
}

bool IsMouseMovementNatural(const std::vector<AdvancedClickData>& recent) {
    if (recent.size() < 5) return true;

    int movingCount = 0;
    for (const auto& click : recent) {
        if (click.wasMoving) movingCount++;
    }

    // Si menos del 30% de los clics involucran movimiento, puede ser macro
    double movementRatio = static_cast<double>(movingCount) / recent.size();
    return movementRatio > 0.3;
}

//----------------------------------------------------------------------
// FUNCIÓN PRINCIPAL DE DETECCIÓN MEJORADA
//----------------------------------------------------------------------

int AnalyzeMacroSuspicion(const std::vector<AdvancedClickData>& clickData) {
    if (clickData.size() < MIN_SAMPLE_SIZE) return 0;

    // Extraer solo los timings para análisis
    std::vector<double> timings;
    for (size_t i = 1; i < clickData.size(); i++) {
        timings.push_back(clickData[i].timeDiff);
    }

    int suspicionPoints = 0;

    // 1. Análisis de coeficiente de variación
    double cv = CalculateCoefficientOfVariation(timings);
    if (cv < COEFFICIENT_VARIATION_THRESHOLD) {
        suspicionPoints += 25; // Patrón muy regular
    }

    // 2. Análisis de autocorrelación
    double autocorr = CalculateAutocorrelation(timings);
    if (autocorr > AUTOCORRELATION_THRESHOLD) {
        suspicionPoints += 20; // Patrones repetitivos
    }

    // 3. Análisis de entropía
    double entropy = CalculateEntropy(timings);
    if (entropy < 2.5) { // Baja entropía indica patrones predecibles
        suspicionPoints += 20;
    }

    // 4. Detección de patrones fijos
    if (DetectFixedPatterns(timings)) {
        suspicionPoints += 25;
    }

    // 5. Análisis de límites físicos
    int tooFastCount = 0;
    for (double timing : timings) {
        if (timing < MIN_HUMAN_INTERVAL_MS) {
            tooFastCount++;
        }
    }
    if (tooFastCount > timings.size() * 0.1) { // Más del 10% demasiado rápido
        suspicionPoints += 15;
    }

    // 6. Análisis de movimiento del mouse
    if (!IsMouseMovementNatural(clickData)) {
        suspicionPoints += 10;
    }

    // 7. Comparación con baseline del usuario (solo después de calibración)
    if (!isCalibrating && userBaselineVariance > 0) {
        double currentVariance = 0.0;
        double mean = std::accumulate(timings.begin(), timings.end(), 0.0) / timings.size();
        for (double timing : timings) {
            currentVariance += (timing - mean) * (timing - mean);
        }
        currentVariance /= (timings.size() - 1);

        // Si la varianza actual es mucho menor que el baseline del usuario
        if (currentVariance < userBaselineVariance * 0.3) {
            suspicionPoints += 15;
        }
    }

    return (std::min)(suspicionPoints, 100); // Máximo 100 puntos
}

//----------------------------------------------------------------------
// HOOK DEL MOUSE MEJORADO
//----------------------------------------------------------------------



// Estructura para tracking de clics
struct ClickData {
    POINT position;
    std::chrono::steady_clock::time_point timestamp;
};
std::vector<ClickData> clickHistory;

//----------------------------------------------------------------------
// LISTA BLANCA DE DLLs
//----------------------------------------------------------------------

std::vector<std::string> whiteListDLLs = {
    // === DLLs del Sistema Windows (A-Z) ===
    "_etoured.dll",
    "advapi32.dll",
    "agperfmon.dll",
    "aimem.dll",
    "amdihk32.dll",
    "amdxn32.dll",
    "amdxx32.dll",
    "amsi.dll",
    "amsiext_x86.dll",
    "antimalware_provider.dll",
    "api-ms-win-downlevel-advapi32-l2-1-0.dll",
    "api-ms-win-downlevel-ole32-l1-1-0.dll",
    "api-ms-win-downlevel-shell32-l1-1-0.dll",
    "api-ms-win-downlevel-shlwapi-l2-1-0.dll",
    "apphelp.dll",
    "aswamsi.dll",
    "aticfx32.dll",
    "atidx9loader32.dll",
    "atidxx32.dll",
    "atiu9pag.dll",
    "atiumdag.dll",
    "atiumdva.dll",
    "atiumdvt.dll",
    "atiuxpag.dll",
    "audioses.dll",
    "avamsi.dll",
    "avrt.dll",

    // === DLLs del Sistema Windows (B-C) ===
    "bcap32.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "bdcam32.dll",
    "bdcap32.dll",
    "cfgmgr32.dll",
    "cldapi.dll",
    "clbcatq.dll",
    "com_antivirus.dll",
    "coremessaging.dll",
    "coreprivacysettingsstore.dll",
    "coreuicomponents.dll",
    "controllib32.dll",
    "crashtrace.dll",
    "credssp.dll",
    "crypt32.dll",
    "cryptnet.dll",
    "cscapi.dll",

    // === DLLs del Sistema Windows (D) ===
    "d2d1.dll",
    "d3d9.dll",
    "d3d9on12.dll",
    "d3d10.dll",
    "d3d10_1.dll",
    "d3d10_1core.dll",
    "d3d10core.dll",
    "d3d10warp.dll",
    "d3d11.dll",
    "d3d12.dll",
    "d3d12core.dll",
    "d3dcompiler_47.dll",
    "d3dcompiler_47_32.dll",
    "d3dscache.dll",
    "d3dx9_31.dll",
    "dcomp.dll",
    "dciman32.dll",
    "ddraw.dll",
    "devobj.dll",
    "dg.dll",
    "dhcpcsvc.dll",
    "dhcpcsvc6.dll",
    "diagnosticdatasettings.dll",
    "dinput8.dll",
    "directxdatabasehelper.dll",
    "discordhook.dll",
    "dnsapi.dll",
    "dpapi.dll",
    "drvstore.dll",
    "dwrite.dll",
    "dwmapi.dll",
    "dxcore.dll",
    "dxgi.dll",
    "dxilconv.dll",

    // === DLLs del Sistema Windows (E-G) ===
    "eamsi.dll",
    "easyhook.dll",
    "edputil.dll",
    "fastprox.dll",
    "firewallapi.dll",
    "fortiamsi.dll",
    "fwbase.dll",
    "fwpolicyiomgr.dll",
    "fwpuclnt.dll",
    "game_detour_32.dll",
    "gamemode.dll",
    "gameshielddll.dll",
    "gdi32.dll",
    "glu32.dll",
    "gpapi.dll",
    "graphics-hook32.dll",

    // === DLLs del Sistema Windows (H-I) ===
    "hid.dll",
    "ieapfitr.dll",
    "ieapfltr.dll",
    "ieframe.dll",
    "iertutil.dll",
    "igd9dxva32.dll",
    "igd9trinity32.dll",
    "igd12dxva32.dll",
    "igd12um32xel.dll",
    "igd12umd32.dll",
    "igc32.dll",
    "igddxvacommon32.dll",
    "igdgmm32.dll",
    "igdinfo32.dll",
    "igdml32.dll",
    "igdumd32.dll",
    "igdumdim32.dll",
    "igdumdx32.dll",
    "igdusc32.dll",
    "imagehlp.dll",
    "imkrtip.dll",
    "imm32.dll",
    "inputhost.dll",
    "intelcontrollib32.dll",

    // === DLLs del Sistema Windows (J-M) ===
    "jscript9.dll",
    "kernel32.dll",
    "libeay32.dll",
    "libprotobuf.dll",
    "mc-sec-plugin-x86.dll",
    "mdnsnsp.dll",
    "media_bin_32.dll",
    "medal-hook32.dll",
    "messagebus.dll",
    "microsoft.internal.warppal.dll",
    "mlang.dll",
    "mmdevapi.dll",
    "mpoav.dll",
    "msasn1.dll",
    "msctf.dll",
    "msdbg2.dll",
    "mshtml.dll",
    "msimtf.dll",
    "msiso.dll",
    "mskeyprotect.dll",
    "msvcp100.dll",
    "msvcr100.dll",
    "mswsock.dll",

    // === DLLs del Sistema Windows (N) ===
    "napinsp.dll",
    "ncrypt.dll",
    "ncryptsslp.dll",
    "netprofm.dll",
    "ninput.dll",
    "nlansp_c.dll",
    "nlaapi.dll",
    "normaliz.dll",
    "npmproxy.dll",
    "nsi.dll",
    "ntasn1.dll",
    "ntdll.dll",
    "ntdsapi.dll",
    "ntmarta.dll",
    "nvaihdr.dll",
    "nvaidvc.dll",
    "nvapi.dll",
    "nvcamera32.dll",
    "nvd3d9wrap.dll",
    "nvd3dum.dll",
    "nvdlist.dll",
    "nvgpucomp32.dll",
    "nvinit.dll",
    "nvldumd.dll",
    "nvmemmapstorage.dll",
    "nvppe.dll",
    "nvscpapi.dll",
    "nvspcap.dll",
    "nvumdshim.dll",
    "nvwgf2um.dll",
    "nxcharacter.2.8.1.dll",
    "nxcooking.2.8.1.dll",

    // === DLLs del Sistema Windows (O-P) ===
    "oldnewexplorer32.dll",
    "oleacc.dll",
    "ondemandconnroutehelper.dll",
    "opengl32.dll",
    "owclient.dll",
    "owexplorer.dll",
    "owutils.dll",
    "pdm.dll",
    "physxcore.2.8.1.dll",
    "physxloader.2.8.1.dll",
    "pmls.dll",
    "poco.dll",
    "pocoinitializer.dll",
    "pnrpnsp.dll",
    "profapi.dll",
    "profext.dll",
    "propsys.dll",

    // === DLLs del Sistema Windows (R-S) ===
    "rasadhlp.dll",
    "rasapi32.dll",
    "rasman.dll",
    "resourcepolicyclient.dll",
    "rmclient.dll",
    "rpcrtremote.dll",
    "rtutils.dll",
    "rtsshooks.dll",
    "safemon.dll",
    "safeips.dll",
    "schannel.dll",
    "secur32.dll",
    "sensapi.dll",
    "setupapi.dll",
    "shell32.dll",
    "shlwapi.dll",
    "slc.dll",
    "smgbfilter.dll",
    "sppc.dll",
    "sptip.dll",
    "srpapi.dll",
    "srvcli.dll",
    "ssleay32.dll",
    "sspicli.dll",
    "symamsi.dll",
    "sxs.dll",

    // === DLLs del Sistema Windows (T-U) ===
    "textinputframework.dll",
    "textshaping.dll",
    "twinapi.appcore.dll",
    "uiautomationcore.dll",
    "urlmon.dll",
    "user32.dll",
    "userenv.dll",
    "usermgrcli.dll",
    "uvh.dll",

    // === DLLs del Sistema Windows (V-W) ===
    "verifier.dll",
    "wbemcomn.dll",
    "wbemprox.dll",
    "wbemsvc.dll",
    "webio.dll",
    "windows.fileexplorer.common.dll",
    "windows.staterepositoryps.dll",
    "windows.storage.dll",
    "windows.system.launcher.dll",
    "windows.ui.dll",
    "windowmanagementapi.dll",
    "windowscodecs.dll",
    "winhttp.dll",
    "winmm.dll",
    "winnsi.dll",
    "winrnr.dll",
    "wintrust.dll",
    "wintypes.dll",
    "wkscli.dll",
    "wldp.dll",
    "wlidnsp.dll",
    "wpcwebfilter.dll",
    "wshbth.dll",
    "wship6.dll",
    "wshtcpip.dll",
    "wtdccm.dll",
    "wtsapi32.dll",
    "window.ime",

    // === DLLs del Sistema Windows (X) ===
    "xinput1_4.dll",
    "xinput9_1_0.dll",
    "xsplitgamesource32.dll",

    // === DLLs de Aplicaciones (F) ===
    "fraps32.dll",
    "virtdisk.dll",
    "mpehttpext.dll",
    "dxwnd.dll"
};

//----------------------------------------------------------------------
// PUNTEROS PARA API HOOKING
//----------------------------------------------------------------------

static HANDLE(WINAPI* TrueCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD) = CreateRemoteThread;
static HMODULE(WINAPI* TrueLoadLibraryA)(LPCSTR) = LoadLibraryA;
static HMODULE(WINAPI* TrueLoadLibraryW)(LPCWSTR) = LoadLibraryW;
static LPVOID(WINAPI* TrueVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD) = VirtualAllocEx;
static BOOL(WINAPI* TrueWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = WriteProcessMemory;
static BOOL(WINAPI* TrueReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*) = ReadProcessMemory;
static HMODULE(WINAPI* TrueGetModuleHandleA)(LPCSTR) = GetModuleHandleA;
static HINTERNET(WINAPI* TrueInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD) = InternetOpenA;
static HINTERNET(WINAPI* TrueInternetOpenUrlA)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR) = InternetOpenUrlA;

//----------------------------------------------------------------------
// FUNCIONES AUXILIARES DE CONVERSIÓN Y UTILIDADES
//----------------------------------------------------------------------

void CloseProcessAfterTimeout(int timeoutMs) {
    Sleep(timeoutMs);
    ExitProcess(0);  // Termina el proceso completamente
}

void ShowMessageAndExit(const char* message, const char* title, int timeoutMs) {
    // Crear un hilo para cerrar el proceso después del tiempo especificado
    std::thread(CloseProcessAfterTimeout, timeoutMs).detach();

    // Mostrar el MessageBox (el proceso seguirá ejecutándose hasta que termine el tiempo)
    MessageBoxA(NULL, message, title, MB_ICONWARNING | MB_OK | MB_SYSTEMMODAL | MB_TOPMOST);
}

// Función para guardar logs
void SaveLog(const std::string& logMessage) {
    std::ofstream logFile("dll_injection_log.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << logMessage << std::endl;
        logFile.close();
    }
}

// Funciones de conversión a minúsculas
std::string toLower(const std::string& str) {
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return lowerStr;
}

std::wstring toLower(const std::wstring& str) {
    std::wstring lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
        [](wchar_t c) { return std::tolower(c); });
    return lowerStr;
}

// Conversiones entre string y wstring
// Versión mejorada de WCharToString
std::string WCharToString(const WCHAR* wchar) {
    if (wchar == nullptr) return std::string();

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wchar, -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) return std::string();

    std::string strTo(size_needed - 1, 0); // -1 para excluir el null terminator
    WideCharToMultiByte(CP_UTF8, 0, wchar, -1, &strTo[0], size_needed, nullptr, nullptr);

    // Asegurarnos de que no haya caracteres nulos en medio de la cadena
    size_t pos = strTo.find('\0');
    if (pos != std::string::npos) {
        strTo.resize(pos);
    }

    return strTo;
}

// Alternativa usando función específica para el nombre del proceso
std::string SafeProcessNameToString(const WCHAR* processName) {
    if (processName == nullptr) return "unknown";

    std::wstring ws(processName);
    std::string result;
    result.reserve(ws.length()); // Reservar espacio para eficiencia

    for (wchar_t wc : ws) {
        if (wc > 127) {
            // Caracteres no ASCII - reemplazar con un carácter seguro
            result += '_';
        }
        else if (wc == 0) {
            // Encontramos un null terminator - terminar aquí
            break;
        }
        else {
            // Caracteres ASCII normales
            result += static_cast<char>(wc);
        }
    }

    return result;
}
 
std::string wstringToString(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

std::wstring stringToWstring(const std::string& str) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(str);
}

LPCWSTR ConvertToLPCWSTR(const char* str) {
    int length = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
    wchar_t* wideStr = new wchar_t[length];
    MultiByteToWideChar(CP_ACP, 0, str, -1, wideStr, length);
    return wideStr;
}

// Funciones utilitarias para DLLs
std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string GetFileName(const std::string& filePath) {
    size_t lastSlash = filePath.find_last_of("\\/");
    return (lastSlash != std::string::npos) ? filePath.substr(lastSlash + 1) : filePath;
}

//----------------------------------------------------------------------
// FUNCIONES DE COMUNICACIÓN IPC
//----------------------------------------------------------------------

bool ConnectToPipe() {
    // Cerrar el pipe si ya está abierto
    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
        hPipe = INVALID_HANDLE_VALUE;
    }

    // Espera hasta 5 segundos si el servidor no está listo
    if (!WaitNamedPipeA(PIPE_NAME, 10000)) {
        std::cerr << "[!] Servidor de pipe no disponible. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Intentar conectar - solo modo escritura para simplificar
    hPipe = CreateFileA(
        PIPE_NAME,
        GENERIC_WRITE,
        0,              // No compartir
        NULL,           // Seguridad por defecto
        OPEN_EXISTING,  // Solo abre si existe
        0,              // Modo síncrono - más simple para depurar
        NULL            // Sin plantilla
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::cerr << "[!] Error al conectar al pipe: " << error << std::endl;
        return false;
    }

    std::cout << "[+] Conectado exitosamente al pipe." << std::endl;
    return true;
}

bool SendMessageToPipe(const std::string& message) {
    // Verificar si tenemos un pipe válido
    if (hPipe == INVALID_HANDLE_VALUE) {
        // Si no tenemos conexión, intentar conectar
        if (!ConnectToPipe()) {
            return false;
        }
    }

    // Verificación adicional para evitar advertencias
    if (hPipe == INVALID_HANDLE_VALUE || hPipe == NULL) {
        return false;
    }

    // Escribir mensaje - uso síncrono simple
    DWORD bytesWritten = 0;
    if (!WriteFile(hPipe, message.c_str(), static_cast<DWORD>(message.length()), &bytesWritten, NULL)) {
        DWORD error = GetLastError();

        // Si hay error en la escritura, cerrar y reconectar
        std::cerr << "[!] Error al escribir en el pipe: " << error << std::endl;

        // Verificar que el handle sea válido antes de cerrarlo
        if (hPipe != INVALID_HANDLE_VALUE && hPipe != NULL) {
            CloseHandle(hPipe);
        }

        hPipe = INVALID_HANDLE_VALUE;

        // Intentar reconectar y reenviar
        if (ConnectToPipe()) {
            if (WriteFile(hPipe, message.c_str(), static_cast<DWORD>(message.length()), &bytesWritten, NULL)) {
                return true;
            }
        }
        return false;
    }

    return (bytesWritten == message.length());
}

//----------------------------------------------------------------------
// FUNCIONES DE DETECCIÓN DE DLLs Y PROCESOS
//----------------------------------------------------------------------

bool IsDLLWhitelisted(const std::string& dllName) {
    std::string lowerDllName = ToLower(dllName);

    // Verificar contra la lista blanca completa
    for (const auto& whiteDLL : whiteListDLLs) {
        if (ToLower(whiteDLL) == lowerDllName) {
            return true;
        }
    }

    // Verificar patrones adicionales de DLLs del sistema
    if (lowerDllName.find("api-ms-win-") == 0 ||           // DLLs de API de Windows
        lowerDllName.find("ext-ms-") == 0 ||               // Extensiones de Windows
        lowerDllName.find("windows.") == 0 ||              // DLLs de Windows modernas
        lowerDllName.find("microsoft.") == 0) {            // DLLs de Microsoft
        return true;
    }

    return false;
}

// Obtiene la lista de DLLs cargadas en el proceso
std::vector<std::string> GetLoadedDLLs() {
    std::vector<std::string> dllList;
    HANDLE hProcess = GetCurrentProcess();
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                std::string dllName = ToLower(GetFileName(std::string(szModName)));

                // Solo agregar DLLs que NO están en la lista blanca
                if (!IsDLLWhitelisted(dllName)) {
                    dllList.push_back(dllName);
                }
            }
        }
    }
    return dllList;
}

void ScanHiddenModules() 
{
    DWORD processId = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);

    std::vector<std::string> listedModules;
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnap, &me32)) {
        do {
            std::string moduleName = WCharToString(me32.szModule);
            listedModules.push_back(ToLower(moduleName));
        } while (Module32Next(hSnap, &me32));
    }

    CloseHandle(hSnap);

    // Verificar si hay módulos cargados que no aparecen en la lista de snapshots
    std::vector<std::string> currentDLLs = GetLoadedDLLs();
    for (const auto& dll : currentDLLs) {
        if (std::find(listedModules.begin(), listedModules.end(), ToLower(dll)) == listedModules.end()) {
            // ¡Módulo oculto detectado!
            json jsonMessage = {
                {"action", "REPORT_DLL"},
                {"message", "Módulo oculto detectado: " + dll}
            };

            SendMessageToPipe(jsonMessage.dump());
            // Considerar terminar el proceso aquí
        }
    }
}

LRESULT CALLBACK ImprovedMouseHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_LBUTTONDOWN && !isProcessingSuspension) {
        auto currentTime = std::chrono::high_resolution_clock::now();
        MSLLHOOKSTRUCT* mouseInfo = (MSLLHOOKSTRUCT*)lParam;
        POINT cursorPos = mouseInfo->pt;

        // Calcular datos del clic actual
        AdvancedClickData currentClick;
        currentClick.position = cursorPos;
        currentClick.timestamp = currentTime;
        currentClick.timeDiff = 0.0;
        currentClick.movementSpeed = 0.0;
        currentClick.wasMoving = false;

        if (!advancedClickHistory.empty()) {
            auto lastClick = advancedClickHistory.back();
            auto timeDiff = std::chrono::duration_cast<std::chrono::milliseconds>(
                currentTime - lastClick.timestamp).count();

            currentClick.timeDiff = static_cast<double>(timeDiff);
            currentClick.movementSpeed = CalculateMovementSpeed(
                lastClick.position, cursorPos, currentClick.timeDiff);
            currentClick.wasMoving = currentClick.movementSpeed > 0.1; // > 0.1 pixels/ms
        }

        // Verificar entrada inyectada
        if (mouseInfo->flags & LLMHF_INJECTED) {
            suspicionScore += 30; // Penalización inmediata por entrada inyectada

            json jsonMessage = {
                {"action", "INJECTION_ALERT"},
                {"message", "Entrada de mouse inyectada detectada"}
            };
            SendMessageToPipe(jsonMessage.dump());
        }

        // Agregar a historial
        advancedClickHistory.push_back(currentClick);
        if (advancedClickHistory.size() > HISTORY_SIZE) {
            advancedClickHistory.erase(advancedClickHistory.begin());
        }

        // Período de calibración inicial
        if (IsInCalibrationPeriod()) {
            calibrationStart = std::chrono::steady_clock::now();
            legitClicksCount++;

            // Finalizar calibración si tenemos suficientes datos
            if (legitClicksCount >= 200 ||
                std::chrono::duration_cast<std::chrono::minutes>(
                    currentTime - calibrationStart).count() >= 10) {

                isCalibrating = false;
                std::vector<double> calibrationTimings;
                for (size_t i = 1; i < advancedClickHistory.size(); i++) {
                    calibrationTimings.push_back(advancedClickHistory[i].timeDiff);
                }
                UpdateUserBaseline(calibrationTimings);
            }

            return CallNextHookEx(NULL, nCode, wParam, lParam);
        }

        // Análisis principal (solo después de calibración)
        if (advancedClickHistory.size() >= MIN_SAMPLE_SIZE) {
            int currentSuspicion = AnalyzeMacroSuspicion(advancedClickHistory);

            // Sistema de puntuación acumulativa con decaimiento
            suspicionScore = static_cast<int>(suspicionScore * 0.95) + (currentSuspicion / 5);
            suspicionScore = (std::min)(suspicionScore, 100);

            // Manejo graduado de sospechas
            if (suspicionScore >= CRITICAL_THRESHOLD) {
                char message[200];
                sprintf_s(message,
                    "Macro detectado con alta confianza (puntuación: %d/100)\n"
                    "CV: %.3f, Entropía: %.2f",
                    suspicionScore,
                    CalculateCoefficientOfVariation(std::vector<double>()),
                    CalculateEntropy(std::vector<double>()));

                ShowMessageAndExit(message, "ALERTA DE MACRO CRÍTICA", 8000);
                return 1; // Bloquear el clic
            }
            else if (suspicionScore >= SUSPICION_THRESHOLD) {
                // Advertencia suave - registrar pero no bloquear
                json jsonMessage = {
                    {"action", "MACRO_WARNING"},
                    {"message", "Patrón de clics sospechoso detectado"},
                    {"suspicion_score", suspicionScore}
                };
                SendMessageToPipe(jsonMessage.dump());

                // Reducir puntuación gradualmente si no hay más evidencia
                suspicionScore = static_cast<int>(suspicionScore * 0.9);
            }

            // Reset periódico para evitar acumulación excesiva
            static int clicksSinceReset = 0;
            clicksSinceReset++;
            if (clicksSinceReset > 1000) {
                suspicionScore = (std::max)(0, suspicionScore - 10);
                clicksSinceReset = 0;
            }
        }
    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

void InitializeImprovedAntiMacro() {
    // Inicializar variables
    advancedClickHistory.clear();
    baselineTimings.clear();
    suspicionScore = 0;
    isCalibrating = true;
    calibrationStart = std::chrono::steady_clock::now();
    legitClicksCount = 0;

    // Crear console para debug (opcional)
#ifdef _DEBUG
    CreateConsole();
    std::cout << "[+] Sistema anti-macro mejorado inicializado" << std::endl;
    std::cout << "[+] Entrando en período de calibración (10 min o 200 clics)" << std::endl;
#endif
}

bool CheckIATIntegrity() {
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) return false;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

    // Verificar la tabla de importación
    DWORD importRVA = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importRVA == 0) return true;  // No hay importaciones, lo cual es raro pero puede ser válido

    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importRVA);

    // Recorrer cada DLL importada
    for (; importDesc->Name != 0; importDesc++) {
        LPCSTR dllName = (LPCSTR)((BYTE*)hModule + importDesc->Name);

        // Verificar si la DLL es crítica para el sistema
        std::string dllNameStr = toLower(dllName);
        if (dllNameStr == "kernel32.dll" || dllNameStr == "ntdll.dll") {
            // Verificar las funciones importadas
            if (importDesc->FirstThunk == 0 || importDesc->OriginalFirstThunk == 0)
                continue;  // Protección contra errores

            PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
            PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);

            // Recorrer las funciones importadas
            while (origThunk->u1.AddressOfData != 0 && firstThunk->u1.Function != 0) {
                // Verificar si es una importación por nombre
                if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + origThunk->u1.AddressOfData);
                    std::string funcName = (char*)importByName->Name;

                    // Comprobar hooks en funciones críticas
                    if (funcName.find("VirtualAlloc") != std::string::npos ||
                        funcName.find("WriteProcessMemory") != std::string::npos ||
                        funcName.find("ReadProcessMemory") != std::string::npos ||
                        funcName.find("CreateRemoteThread") != std::string::npos) {

                        // Analizar los primeros bytes para detectar JMP
                        BYTE* funcAddr = (BYTE*)firstThunk->u1.Function;
                        if (funcAddr[0] == 0xE9 || funcAddr[0] == 0xEB) {  // JMP o JMP SHORT
                            SaveLog("Hook detectado en función crítica: " + funcName);
							std::cout << "[!] Hook detectado en función crítica: " << funcName << std::endl;
                            return false;
                        }
                    }
                }

                firstThunk++;
                origThunk++;
            }
        }
    }

    return true;
}

void ProtectCodeRegions() {
    HMODULE hModule = GetModuleHandle(NULL);
    if (!hModule) return;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

    DWORD codeStart = (DWORD)hModule + ntHeader->OptionalHeader.BaseOfCode;
    DWORD codeSize = ntHeader->OptionalHeader.SizeOfCode;

    // Tomar un hash inicial de la región de código
    std::vector<BYTE> codeRegion(codeSize);
    memcpy(codeRegion.data(), (void*)codeStart, codeSize);

    // Programar verificaciones periódicas
    std::thread([=]() {
        std::vector<BYTE> currentCode(codeSize);
        while (!stopThread) {
            memcpy(currentCode.data(), (void*)codeStart, codeSize);

            if (memcmp(codeRegion.data(), currentCode.data(), codeSize) != 0) {
                // ¡Modificación de código detectada!
                json jsonMessage = {
                    {"action", "CHEAT_REPORT"},
                    {"message", "Se detectó manipulación de código en memoria"}
                };

                SendMessageToPipe(jsonMessage.dump());
            }

            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
        }).detach();
}

bool IsDebuggerPresentAdvanced() {
    // Métodos conocidos
    if (IsDebuggerPresent()) return true;

    BOOL isDebugged = FALSE;
#ifdef _M_IX86  // Solo para compilaciones x86
    __asm {
        push eax
        mov eax, fs: [0x30]
        movzx eax, byte ptr[eax + 0x2]
        mov isDebugged, eax
        pop eax
    }
#else
    // En caso de x64, usar NtQueryInformationProcess
#endif

    // Verificar timing del kernel
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);

    OutputDebugStringA("AntiDebugCheck");

    QueryPerformanceCounter(&end);

    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    if (elapsed > 0.01) return true;  // Demasiado lento, probable debugger

    return false;
}

bool CheckSystemHooks() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    // Lista de funciones que nuestro anticheat hookea legítimamente
    std::vector<std::string> whitelistedHooks = {
        "NtWriteVirtualMemory",     // Hookeado por nuestro WriteProcessMemory
        "NtCreateThreadEx",         // Puede ser hookeado por nuestro CreateRemoteThread
        "LdrLoadDll"                // Puede ser hookeado por nuestro LoadLibrary
    };

    // Lista de funciones críticas de ntdll a verificar
    const char* criticalFunctions[] = {
        "NtQueryInformationProcess",
        "NtCreateFile",
        "NtOpenProcess",
        "NtAllocateVirtualMemory",
        "NtMapViewOfSection",
        "NtReadVirtualMemory"
        // No incluimos las funciones que nosotros hookeamos
    };

    // Verificar cada función crítica
    for (const char* funcName : criticalFunctions) {
        FARPROC pFunc = GetProcAddress(hNtdll, funcName);
        if (pFunc) {
            BYTE* pBytes = (BYTE*)pFunc;

            // Detectar hooks comunes
            if (pBytes[0] == 0xE9 || pBytes[0] == 0xEB) {
                // Verificar si es uno de nuestros hooks permitidos
                std::string strFuncName(funcName);
                if (std::find(whitelistedHooks.begin(), whitelistedHooks.end(), strFuncName) == whitelistedHooks.end()) {


                    SaveLog(std::string("Hook no autorizado detectado en: ") + funcName);
					json jsonMessage = {
						{"action", "INJECTION_ALERT"},
						{"message", std::string("Hook no autorizado detectado en: ") + funcName}
					};
					SendMessageToPipe(jsonMessage.dump());
					std::cout << "[!] Hook no autorizado detectado en: " << funcName << std::endl;
                    return true;
                }
            }
        }
    }

    // Verificar kernel32 excluyendo nuestros propios hooks
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        std::vector<std::string> whitelistedKernel32 = {
            //"CreateProcessA",    // Por si lo hookeamos en el futuro
            //"CreateProcessW",    // Por si lo hookeamos en el futuro
            "LoadLibraryA",      // Ya hookeado por nuestro anticheat
            "LoadLibraryW",      // Ya hookeado por nuestro anticheat
            "WriteProcessMemory", // Ya hookeado por nuestro anticheat
            "CreateRemoteThread"  // Ya hookeado por nuestro anticheat
            "VirtualAllocEx",
        };

        // Funciones adicionales a verificar
        const char* kernel32Functions[] = {
            "GetProcAddress",
            "CreateThread"
        };

        for (const char* funcName : kernel32Functions) {
            FARPROC pFunc = GetProcAddress(hKernel32, funcName);
            if (pFunc) {
                BYTE* pBytes = (BYTE*)pFunc;
                if (pBytes[0] == 0xE9 || pBytes[0] == 0xEB) {
                    std::string strFuncName(funcName);
                    if (std::find(whitelistedKernel32.begin(), whitelistedKernel32.end(), strFuncName) == whitelistedKernel32.end()) {
                        json jsonMessage = {
                            {"action", "INJECTION_ALERT"},
                            {"message", std::string("Hook no autorizado en kernel32: ") + funcName}
                        };
                        SendMessageToPipe(jsonMessage.dump());
                        SaveLog(std::string("Hook no autorizado en kernel32: ") + funcName);
						std::cout << "[!] Hook no autorizado en kernel32: " << funcName << std::endl;
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

bool IsProcessSigned(HANDLE hProcess) {
    WCHAR processPath[MAX_PATH];
    if (GetModuleFileNameEx(hProcess, NULL, processPath, MAX_PATH) == 0) {
        return false;
    }

    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = processPath;

    WINTRUST_DATA winTrustData = { 0 };
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;

    // Usar la GUID correctamente
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG result = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    return (result == ERROR_SUCCESS);
}

bool CheckVMWare() {
    bool result = false;
    __try {
        __asm {
            push edx
            push ecx
            push ebx
            mov eax, 'VMXh'
            mov ebx, 0
            mov ecx, 10
            mov edx, 'VX'
            in eax, dx
            cmp ebx, 'VMXh'
            setz[result]
                pop ebx
                    pop ecx
                    pop edx
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // No es VMware
    }
    return result;
}

bool IsRunningInVM() {

    if (CheckVMWare()) return true;

    // Verificar procesos de VM conocidos
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(entry);

        if (Process32First(snapshot, &entry)) {
            do {
                std::string processName = ToLower(WCharToString(entry.szExeFile));
                if (processName.find("vmtoolsd") != std::string::npos ||
                    processName.find("vboxtray") != std::string::npos ||
                    processName.find("vboxservice") != std::string::npos ||
                    processName.find("vmwareservice") != std::string::npos) {
                    CloseHandle(snapshot);
                    return true;
                }
            } while (Process32Next(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }

    // Verificar el dispositivo VBoxMiniRdrDN
    HANDLE hDevice = CreateFileA("\\\\.\\VBoxMiniRdrDN",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return true;
    }

    return false;
}

// Detecta si una nueva DLL ha sido inyectada en el proceso
void DetectInjectedDLLs(std::vector<std::string>& previousDLLs) {
    std::vector<std::string> currentDLLs = GetLoadedDLLs();

    for (const std::string& dll : currentDLLs) {
        if (std::find(previousDLLs.begin(), previousDLLs.end(), dll) == previousDLLs.end()) {
            // Si la DLL no estaba en la lista antes, probablemente fue inyectada
            if (std::find_if(whiteListDLLs.begin(), whiteListDLLs.end(),
                [&dll](const std::string& wl) { return ToLower(wl) == dll; })
                == whiteListDLLs.end()) {

                std::string alertMessage = "[ALERTA] Se detecto una nueva DLL inyectada: " + dll;
                json jsonMessage = {
                    {"action", "INJECTION_ALERT"},
                    {"message", "Reporte Dll no registrada cargada: " + dll}
                };


                // Convertir el mensaje a formato JSON y enviarlo
                std::string msg = jsonMessage.dump();
                SendMessageToPipe(msg);

                ShowMessageAndExit(alertMessage.c_str(), "ALERTA DE INYECCION",8000);
            }
        }
    }
    previousDLLs = currentDLLs;
}

// Function to search for a specific pattern in memory
inline bool FindPattern(const BYTE* memory, SIZE_T memorySize, const std::vector<BYTE>& pattern,
    const char* mask) {

    if (!memory || memorySize < pattern.size() || pattern.empty()) return false;

    const size_t patternSize = pattern.size();
    const SIZE_T searchLimit = memorySize - patternSize;

    for (SIZE_T i = 0; i <= searchLimit; i++) {
        bool found = true;

        for (size_t j = 0; j < patternSize; j++) {
            if (mask[j] == 'x' && memory[i + j] != pattern[j]) {
                found = false;
                break;
            }
        }

        if (found) return true;
    }

    return false;
}

// Helper function to convert hex string to byte array
bool HexStringToBytes(const std::string& hexString, std::vector<BYTE>& outBytes) {
    outBytes.clear();
    outBytes.reserve(hexString.length() / 2); // Pre-allocate

    for (size_t i = 0; i < hexString.length(); i += 2) {
        if (i + 1 >= hexString.length()) break;

        char high = hexString[i];
        char low = hexString[i + 1];

        // Skip spaces
        if (high == ' ' || low == ' ') {
            i--;
            continue;
        }

        BYTE value = 0;

        // Convert high nibble
        if (high >= '0' && high <= '9') value = (high - '0') << 4;
        else if (high >= 'a' && high <= 'f') value = (high - 'a' + 10) << 4;
        else if (high >= 'A' && high <= 'F') value = (high - 'A' + 10) << 4;
        else continue;

        // Convert low nibble
        if (low >= '0' && low <= '9') value |= (low - '0');
        else if (low >= 'a' && low <= 'f') value |= (low - 'a' + 10);
        else if (low >= 'A' && low <= 'F') value |= (low - 'A' + 10);
        else continue;

        outBytes.push_back(value);
    }

    return !outBytes.empty();
}

// Main function to detect cheat signatures


const std::vector<std::string> knownFalsePositiveDLLs = {
    "helper.dll",     // Nuestra propia DLL anticheat
    "dsound.dll",     // DirectSound puede tener falsos positivos
    "d3d9.dll",       // DirectX puede tener falsos positivos
    "kernel32.dll",
    "user32.dll",
    "ntdll.dll",
    "PhysXLoader.2.8.1.dll",
    "CrashTrace.dll",
    "NxCharacter.2.8.1.dll",
    "KERNELBASE.dll",
    "dbghelp.dll",
};

bool IsFalsePositiveDLL(const std::string& dllName) {
    std::string lowerDllName = ToLower(dllName);

    for (const auto& falseDLL : knownFalsePositiveDLLs) {
        if (lowerDllName == ToLower(falseDLL)) {
            return true;
        }
    }

    return false;
}

struct CheatSignature {
    const char* name;
    const char* hexPattern;
    const char* mask;
    int confidenceValue;
};

static const CheatSignature optimizedSignatures[] = {
    // Aimbots - alta prioridad
    { "Silent_Aimbot", "53 69 6c 65 6e 74 20 41 69 6d 62 6f 74", "xxxxxxxxxxxxx", 4 }, // "Silent Aimbot"
    { "Aimbot", "41 69 6d 62 6f 74", "xxxxxx", 4 },          // "Aimbot"
    { "Aimbot1", "61 69 6d 62 6f 74 31", "xxxxxxx", 4 },     // "aimbot1"
    { "Aimbot2", "61 69 6d 62 6f 74 32", "xxxxxxx", 4 },     // "aimbot2"
    { "AimTargets", "23 23 41 69 6d 54 61 72 67 65 74 53", "xxxxxxxxxxxx", 4 }, // "##AimTargetS"
    { "AimKeys", "23 23 41 69 6d 4b 65 79 53", "xxxxxxxxx", 4 },        // "##AimKeyS"
    { "aimbot", "61 69 6d 62 6f 74", "xxxxxx", 4 },

    // ESP/Wall hacks - prioridad media
    { "ESP_Box", "45 53 50 20 42 6f 78", "xxxxxxx", 4 },                // "ESP Box"
    { "ESP_Line", "45 53 50 20 4c 69 6e 65", "xxxxxxxx", 4 },          // "ESP Line"
    { "ESP_Name", "45 53 50 20 4e 61 6d 65", "xxxxxxxx", 4 },           // "ESP Name"
    { "ESP_Skeleton", "45 53 50 20 53 6b 65 6c 65 74 6f 6e", "xxxxxxxxxxxx", 4 },  // "ESP Skeleton"
    { "ESP_Distance", "45 53 50 20 44 69 73 74 61 6e 63 65", "xxxxxxxxxxxx", 4 },  // "ESP Distance"
    { "ESP_Rank", "45 53 50 20 52 61 6e 6b", "xxxxxxxx", 4 },           // "ESP Rank"
    { "ESP_Health", "45 53 50 20 48 65 61 6c 74 68", "xxxxxxxxxx", 4 },  // "ESP Health"
    { "ESP_Bomb", "45 53 50 20 42 6f 6d 62", "xxxxxxxx", 4 },           // "ESP Bomb"

    // No-recoil, speed hacks - prioridad media-alta
    { "No_Recoil_V", "4e 6f 20 52 65 63 6f 69 6c 20 56", "xxxxxxxxxxx", 4 }, // "No Recoil V"
    { "No_Recoil_H", "4e 6f 20 52 65 63 6f 69 6c 20 48", "xxxxxxxxxxx", 4 }, // "No Recoil H"
    { "Throw_Speed", "54 68 72 6f 77 20 53 70 65 65 64", "xxxxxxxxxxx", 4 }, // "Throw Speed"
    { "Fast_Change", "46 61 73 74 20 63 68 61 6e 67 65", "xxxxxxxxxxx", 4 }, // "Fast change"

    // FPS-related cheats - prioridad baja-media
    { "FPS_MAX", "46 50 53 20 4d 41 58", "xxxxxxx", 4 },     // "FPS MAX"
    { "FPSPRO", "46 50 53 50 52 4f", "xxxxxx", 4 },          // "FPSPRO"
    { "FPSLATINO", "46 00 50 00 53 00 4c 00 41", "xxxxxxxxx", 4 },
    { "PB_BR_VIP", "50 42 20 42 52 20 56 49 50", "xxxxxxxxx", 4 }, // "PB BR VIP"

    { "secret123", "73 65 63 72 65 74 31 32 33", "xxxxxxxxx", 4 },
    { "dimarco", "64 69 6d 61 72 63 6f", "xxxxxxx", 4 },
    { "Dimarco", "44 69 6d 61 72 63 6f", "xxxxxxx", 4 },
    { "Dimarco77", "44 69 6d 61 72 63 6f 37 37", "xxxxxxxxx", 4 },
    { "dimarco77", "64 69 6d 61 72 63 6f 37 37", "xxxxxxxxx", 4 },
    { "PlayC.dll", "50 6c 61 79 43 2e 64 6c 6c", "xxxxxxxxx", 4 },
    { "I|Jxnmyk[xcwrpPn", "49 7c 4a 78 6e 6d 79 6b 5b 78 63 77 72 70 50 6e", "xxxxxxxxxxxxxxxx", 4 },
    { "KghnGeo|nbhWkU", "4b 67 68 6e 47 65 6f 7c 6e 62 68 57 6b 55", "xxxxxxxxxxxxxx", 4 },
    { "{@}dry}:^nrl?*", "7b 40 7d 64 72 79 7d 3a 5e 6e 72 6c 3f 2a", "xxxxxxxxxxxxxx", 4 },
    { "Play.sys", "50 6c 61 79 2e 73 79 73", "xxxxxxxx", 4 },
    { "PlayC.dll / Play.sys Tidak ada", "50 6c 61 79 43 2e 64 6c 6c 20 2f 20 50 6c 61 79 2e 73 79 73 20 54 69 64 61 6b 20 61 64 61", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 4 },
    { "PLAYCHEATZ", "50 4c 41 59 43 48 45 41 54 5a", "xxxxxxxxxx", 0 },
    { "playcheatz", "70 6c 61 79 63 68 65 61 74 7a", "xxxxxxxxxx", 0 },
    //{ "wall", "77 61 6c 6c", "xxxx", 4 },
    //{ "Wall", "57 61 6c 6c", "xxxx", 4 },
    //{ "ESP", "45 53 50", "xxx", 4 },
    //{ "PointBlank.exe", "50 6f 69 6e 74 42 6c 61 6e 6b 2e 65 78 65", "xxxxxxxxxxxxxx", 1 }
};

static const int SIGNATURE_COUNT = sizeof(optimizedSignatures) / sizeof(optimizedSignatures[0]);

// Cache para patrones compilados (evita recompilar cada vez)
static std::vector<std::vector<BYTE>> compiledPatterns;
static bool patternsCompiled = false;

void CompilePatterns() {
    if (patternsCompiled) return;

    compiledPatterns.reserve(SIGNATURE_COUNT);

    for (int i = 0; i < SIGNATURE_COUNT; i++) {
        std::vector<BYTE> pattern;
        HexStringToBytes(optimizedSignatures[i].hexPattern, pattern);
        compiledPatterns.push_back(std::move(pattern));
    }

    patternsCompiled = true;
}
 // Lista blanca de procesos confiables que no deben ser escaneados
 const std::vector<std::string> whiteListProcesses = {
     "explorer.exe",
     "csrss.exe",
     "winlogon.exe",
     "lsass.exe",
     "services.exe",
     "spoolsv.exe",
     "chrome.exe",
     "firefox.exe",
     "msedge.exe",
     "nvcontainer.exe",
     "discord.exe",
     "steam.exe",
     "spotify.exe",
     "RuntimeBroker.exe",
     "audiodg.exe",
     "dwm.exe",
     "SystemSettings.exe",
     "SearchApp.exe",
     "ShellExperienceHost.exe",
     "TextInputHost.exe",
     "GameBar.exe",
     "GameBarFTServer.exe",
     "WindowsInternal.ComposableShell.Experiences.TextInput.InputApp.exe",
     "ServiceHub.VSDetouredHost.exe",
     "ServiceHub.IndexingService.exe"
     "ServiceHub.IdentityHost.exe",
     "Microsoft.ServiceHub.Controller.exe",
     "ServiceHub.RoslynCodeAnalysisService.exe",
     "ServiceHub.ThreadedWaitDialog.exe",
     "ServiceHub.IntellicodeModelService.exe",
     "ServiceHub.Host.dotnet.x64.exe",
     "ServiceHub.TestWindowStoreHost.exe",
     "vctip.exe",
     "opilot-language-server.exe",
     "devenv.exe",
     "WsaClient.exe",
	 "WsaService.exe",
     "UninstallMonitor.exe",
     "GameManagerService3.exe",
     "windows.system.launcher.dll",

     // Procesos adicionales de tu sistema
     "AsusCertService.exe",
     "atkexComSvc.exe",
     "fbguard.exe",
     "ArmouryCrate.Service.exe",
     "HTTPDebuggerSvc.exe",
     "pg_ctl.exe",
     "ROGLiveService.exe",
     "GameSDK.exe",
     "vmware-usbarbitrator64.exe",
     "AsusFanControlService.exe",
     "RvControlSvc.exe",
     "vmware-authd.exe",
     "LightingService.exe",
     "gamingservicesnet.exe",
     "fbserver.exe",
     "postgres.exe",
     "EzUpdt.exe",
     "DipAwayMode.exe",
     "ArmourySocketServer.exe",
     "AISuite3.exe",
     "AcPowerNotification.exe",
     "Aac3572DramHal_x86.exe",
     "extensionCardHal_x86.exe",
     "AacKingstonDramHal_x86.exe",
     "avpui.exe",
     "SpotifyWidgetProvider.exe",
     "Aac3572MbHal_x86.exe",
     "avp.exe",
     "AacKingstonDramHal_x64.exe",
     "vmware-tray.exe",
     "WSACrashUploader.exe",
     "EncoderServer.exe",
     "conhost.exe",
     "WmiPrvSE.exe",
     "ibtsiva.exe",
     "vmnetdhcp.exe",
     "vmnat.exe",
     "RtkAudUService64.exe",
     "jhi_service.exe",
     "WMIRegistrationService.exe",
     "sihost.exe",
     "taskhostw.exe",
     "ctfmon.exe",
     "asus_framework.exe",
     "AggregatorHost.exe",
     "StartMenuExperienceHost.exe",
     "unsecapp.exe",
     "ArmouryCrate.UserSessionHelper.exe",
     "MSIAfterburner.exe",
     "RTSS.exe",
     "CCleaner64.exe",
     "vmcompute.exe",
     "LsaIso.exe",
     "fontdrvhost.exe",
     "NVDisplay.Container.exe",
     "SearchIndexer.exe", 
     "RTSSHooksLoader64.exe",

     "vcpkgsrv.exe",
     "AntiCheat.exe",
     "WindowsServices.exe",
     "mspdbsrv.exe",
     "MSBuild.exe",
     "vcpkgsrv.exe",
     "ArmourySwAgent.exe",


 };

 // Función para verificar si un proceso es conocido por generar falsos positivos
 bool IsFalsePositiveProcess(const std::string& processName) {
     // Lista de procesos conocidos por generar falsos positivos
     static const std::vector<std::string> falsePositiveProcesses = {
         // Procesos del sistema que pueden contener patrones similares a cheats
         "nvapi.exe",                  // NVIDIA API
         "nvapiserver.exe",            // NVIDIA API Server
         "nahimic.exe",                // Nahimic Audio
         "nahimicservice.exe",         // Nahimic Audio Service
         "rgbfusion.exe",              // RGB Fusion (software de iluminación)
         "icue.exe",                   // Corsair iCUE
         "armoury crate.exe",          // ASUS Armoury Crate
         "radeonrx580.exe",            // Software AMD Radeon
         "rtss.exe",                   // RivaTuner Statistics Server
         "msiafterburner.exe",         // MSI Afterburner
         "fraps.exe",                  // Fraps
         "obs.exe",                    // OBS Studio
         "obs64.exe",                  // OBS Studio 64-bit
         "shadowplay.exe",             // NVIDIA ShadowPlay
         "geforceexperience.exe",      // NVIDIA GeForce Experience
         "amd radeon software.exe",    // AMD Radeon Software
         "steamwebhelper.exe",         // Steam Web Helper
         "steam client bootstrapper.exe", // Steam Client Bootstrapper
         "steam.exe",                  // Steam Client
         "steamservice.exe",           // Steam Service
         "epicgameslauncher.exe",      // Epic Games Launcher
         "easyanticheat.exe",          // Easy Anti-Cheat
         "battleye.exe",               // BattlEye
         "valorant.exe",               // Valorant (tiene su propio anti-cheat)
         "vanguard.exe",               // Riot Vanguard
         "faceit.exe",                 // FACEIT
         "faceitclient.exe",           // FACEIT Client
         "esea.exe",                   // ESEA
         "windowsdefender.exe",        // Windows Defender
         "msmpeng.exe",                // Microsoft Malware Protection Engine
         "mrt.exe",                    // Microsoft Malicious Software Removal Tool
         "voicemeeter.exe",            // VoiceMeeter
         "voicemeeteraux.exe",         // VoiceMeeter Auxiliary
         "voicemeeterpro.exe",         // VoiceMeeter Pro
         "apo-driver.exe",             // APO Driver
         "gamebar.exe",                // Xbox Game Bar
         "gamebarft.exe",              // Xbox Game Bar FT
         "gameinputsvc.exe",           // Game Input Service
         "gamingservices.exe",
         "pointblank.exe"              // Gaming Services
     };

     // Convertir el nombre del proceso a minúsculas para comparación case-insensitive
     std::string lowerProcessName = ToLower(processName);

     // Verificar si el proceso está en la lista de falsos positivos
     for (const auto& falsePositive : falsePositiveProcesses) {
         if (lowerProcessName == ToLower(falsePositive)) {
             return true;
         }
     }

     // No está en la lista de falsos positivos
     return false;
 }

 // Función auxiliar para obtener el nombre de archivo de una ruta completa
 std::string GetFileName2(const std::string& fullPath) {
     size_t lastSlash = fullPath.find_last_of("\\/");
     if (lastSlash != std::string::npos) {
         return fullPath.substr(lastSlash + 1);
     }
     return fullPath;
 }

 // Función para convertir texto a minúsculas (si no estaba definida ya)
 std::string ToLower2(const std::string& input) {
     std::string result = input;
     std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) { return std::tolower(c); });
     return result;
 }

// Función especializada para detectar cheats en DLLs
 void DetectCheatPatternsInDLLsOptimized() {
     if (!patternsCompiled) CompilePatterns();

     DWORD cbNeeded = 0;
     HMODULE hMods[512]; // Reducido para mejor performance

     if (!EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
         return;
     }

     int moduleCount = (std::min)(static_cast<int>(cbNeeded / sizeof(HMODULE)), 512);

     for (int i = 0; i < moduleCount; i++) {
         char moduleFullPath[MAX_PATH];

         if (!GetModuleFileNameExA(GetCurrentProcess(), hMods[i], moduleFullPath, MAX_PATH)) {
             continue;
         }

         std::string moduleNameStr = GetFileName2(moduleFullPath);

         // Filtros rápidos
         if (IsFalsePositiveDLL(moduleNameStr)) continue;

         // Verificar whitelist rápidamente
         bool isWhitelisted = false;
         std::string lowerModuleName = ToLower2(moduleNameStr);
         for (const auto& whiteDLL : whiteListDLLs) {
             if (lowerModuleName == ToLower2(whiteDLL)) {
                 isWhitelisted = true;
                 break;
             }
         }

         if (isWhitelisted || std::string(moduleFullPath).find("\\Windows\\") != std::string::npos) {
             continue;
         }

         // Obtener info del módulo
         MODULEINFO modInfo;
         if (!GetModuleInformation(GetCurrentProcess(), hMods[i], &modInfo, sizeof(modInfo))) {
             continue;
         }

         // Escanear con buffer más grande para mejor performance
         const SIZE_T BUFFER_SIZE = 16384; // 16KB
         int totalConfidence = 0;
         std::vector<std::string> detectedCheats;

         for (size_t offset = 0; offset < modInfo.SizeOfImage; offset += BUFFER_SIZE) {
             SIZE_T bytesToRead = (std::min)(BUFFER_SIZE, modInfo.SizeOfImage - offset);

             // Usar __try/__except para manejar excepciones de memoria rápidamente
             try {
                 const BYTE* memory = (BYTE*)modInfo.lpBaseOfDll + offset;

                 // Buscar todos los patrones en paralelo
                 for (int j = 0; j < SIGNATURE_COUNT; j++) {
                     if (FindPattern(memory, bytesToRead, compiledPatterns[j],
                         optimizedSignatures[j].mask)) {

                         detectedCheats.push_back(optimizedSignatures[j].name);
                         totalConfidence += optimizedSignatures[j].confidenceValue;

                         // Para critical signatures, reportar inmediatamente
                         if (strcmp(optimizedSignatures[j].name, "Silent_Aimbot") == 0) {
                             json criticalMessage = {
                                 {"action", "INJECTION_ALERT"},
                                 {"message", "CRITICO: Silent Aimbot en " + moduleNameStr}
                             };
                             SendMessageToPipe(criticalMessage.dump());
                             ShowMessageAndExit("Silent Aimbot detectado", "ALERTA CRITICA", 5000);
                             return;
                         }
                     }
                 }
             }
             catch (const std::exception& ex) {
                 // Continuar con el siguiente bloque si hay error de memoria
                 continue;
             }
         }

         // Reportar si hay múltiples detecciones
         if (detectedCheats.size() >= 2 || totalConfidence >= 6) {
             json alertMessage = {
                 {"action", "INJECTION_ALERT"},
                 {"message", "Multiples cheats en " + moduleNameStr}
             };
             SendMessageToPipe(alertMessage.dump());
             ShowMessageAndExit(("Cheats detectados en " + moduleNameStr).c_str(),
                 "ALERTA", 8000);
             return;
         }
     }
 }

 void DetectCheatPatternsInProcessesOptimized() {
     if (!patternsCompiled) CompilePatterns();

     DWORD processes[256]; // Reducido para mejor performance
     DWORD bytesNeeded;

     if (!EnumProcesses(processes, sizeof(processes), &bytesNeeded)) {
         return;
     }

     DWORD processCount = (std::min)(bytesNeeded / sizeof(DWORD), (DWORD)256);

     for (DWORD i = 0; i < processCount; i++) {
         DWORD processId = processes[i];
         if (processId == 0 || processId == GetCurrentProcessId()) continue;

         HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
             FALSE, processId);
         if (!hProcess) continue;

         char processPath[MAX_PATH] = "";
         if (!GetModuleFileNameExA(hProcess, NULL, processPath, MAX_PATH)) {
             CloseHandle(hProcess);
             continue;
         }

         std::string processName = GetFileName2(processPath);

         // Filtros rápidos
         if (IsFalsePositiveProcess(processName)) {
             CloseHandle(hProcess);
             continue;
         }

         // Verificar whitelist rápidamente
         bool isWhitelisted = false;
         std::string lowerProcessName = ToLower2(processName);
         for (const auto& whiteProcess : whiteListProcesses) {
             if (lowerProcessName == ToLower2(whiteProcess)) {
                 isWhitelisted = true;
                 break;
             }
         }

         if (isWhitelisted || strstr(processPath, "\\Windows\\")) {
             CloseHandle(hProcess);
             continue;
         }

         // Escanear solo el módulo principal (más eficiente)
         MODULEINFO modInfo;
         if (GetModuleInformation(hProcess, NULL, &modInfo, sizeof(modInfo))) {

             const SIZE_T BUFFER_SIZE = 8192; // 8KB para procesos externos
             int totalConfidence = 0;

             for (size_t offset = 0; offset < modInfo.SizeOfImage; offset += BUFFER_SIZE) {
                 SIZE_T bytesToRead = (std::min)(BUFFER_SIZE, modInfo.SizeOfImage - offset);

                 static BYTE buffer[8192]; // Buffer estático para mejor performance
                 SIZE_T bytesRead = 0;

                 if (!ReadProcessMemory(hProcess, (BYTE*)modInfo.lpBaseOfDll + offset,
                     buffer, bytesToRead, &bytesRead) || bytesRead == 0) {
                     continue;
                 }

                 // Buscar patrones críticos primero
                 for (int j = 0; j < SIGNATURE_COUNT; j++) {
                     if (optimizedSignatures[j].confidenceValue >= 4 && // Solo críticos
                         FindPattern(buffer, bytesRead, compiledPatterns[j],
                             optimizedSignatures[j].mask)) {

                         totalConfidence += optimizedSignatures[j].confidenceValue;

                         json alertMessage = {
                             {"action", "INJECTION_ALERT"},
                             {"message", "Cheat " + std::string(optimizedSignatures[j].name) +
                                        " en proceso " + processName + " PID:" + std::to_string(processId)}
                         };
                         SendMessageToPipe(alertMessage.dump());

                         // Para críticos, terminar inmediatamente
                         if (strcmp(optimizedSignatures[j].name, "Silent_Aimbot") == 0) {
                             CloseHandle(hProcess);
                             ShowMessageAndExit("Silent Aimbot en proceso externo", "ALERTA", 5000);
                             return;
                         }
                     }
                 }

                 // Si acumulamos mucha confianza, reportar
                 if (totalConfidence >= 8) {
                     CloseHandle(hProcess);
                     ShowMessageAndExit(("Cheats en proceso " + processName).c_str(),
                         "ALERTA", 8000);
                     return;
                 }
             }
         }

         CloseHandle(hProcess);
     }
 }

//----------------------------------------------------------------------
// FUNCIONES DE MANIPULACIÓN DE PROCESOS
//----------------------------------------------------------------------

bool IsServiceRunning() {
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!schSCManager) return false;

    SC_HANDLE schService = OpenService(schSCManager, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!schService) {
        CloseServiceHandle(schSCManager);
        return false;
    }

    SERVICE_STATUS_PROCESS ssStatus;
    DWORD dwBytesNeeded;
    bool isRunning = false;

    if (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssStatus, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        isRunning = (ssStatus.dwCurrentState == SERVICE_RUNNING);
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);

    return isRunning;
}

void ShowMessage(const char* message, const char* title) {
    MessageBoxA(NULL, message, title, MB_OK | MB_ICONINFORMATION);
}

void Start(const std::string& path, const std::string& arg1, const std::string& arg2) {
    std::string exePath = path + "\\HackShield\\AntiCheat.exe";
    std::string arguments = arg1 + " " + arg2;
    std::string workingDir = path + "\\HackShield";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    std::string cmdLine = "\"" + exePath + "\" " + arguments;

    if (!CreateProcessA(
        exePath.c_str(),
        &cmdLine[0],
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE,  // Esta bandera es clave
        NULL,
        workingDir.c_str(),
        &si,
        &pi))
    {
        DWORD error = GetLastError();
        ShowMessageAndExit(("Error al iniciar el proceso. Código: " + std::to_string(error)).c_str(), "Error", 10000);
    }

    // Cerrar handles para evitar fugas
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

//----------------------------------------------------------------------
// FUNCIONES PARA MANIPULACIÓN DE ARCHIVOS Y SERVICIOS
//----------------------------------------------------------------------

void CopyServiceExecutableToTemp() {
    // Obtener la ruta completa del ejecutable actual
    wchar_t exePath[MAX_PATH];
    if (GetModuleFileNameW(NULL, exePath, MAX_PATH) == 0) {
        MessageBoxA(NULL, "Error al obtener la ruta del ejecutable.", "Error", MB_ICONERROR | MB_OK);
        return;
    }

    // Obtener el directorio donde se ejecuta el programa
    std::wstring currentDirectory = exePath;
    size_t lastSlashPos = currentDirectory.find_last_of(L"\\/");

    if (lastSlashPos != std::wstring::npos) {
        currentDirectory = currentDirectory.substr(0, lastSlashPos);
    }

    // Ruta completa del ejecutable fuente
    std::wstring sourcePath = currentDirectory + L"\\Services\\WindowsServices.exe";

    // Obtener la ruta de la carpeta temporal del sistema
    wchar_t tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath) == 0) {
        MessageBoxA(NULL, "Error al obtener la carpeta temporal.", "Error", MB_ICONERROR | MB_OK);
        return;
    }

    // Crear la carpeta "Services" dentro de la carpeta temporal
    std::wstring tempServicesFolder = std::wstring(tempPath) + L"Services";
    std::wstring destPath = tempServicesFolder + L"\\WindowsServices.exe";

    // Verificar si la carpeta de destino existe, si no, crearla
    if (!PathFileExistsW(tempServicesFolder.c_str())) {
        if (!CreateDirectoryW(tempServicesFolder.c_str(), NULL)) {
            MessageBoxA(NULL, "Error al crear la carpeta en TEMP.", "Error", MB_ICONERROR | MB_OK);
            return;
        }
    }

    // Si el archivo ya existe en la ubicación temporal, lo eliminamos antes de copiar el nuevo
    if (PathFileExistsW(destPath.c_str())) {
        if (!DeleteFileW(destPath.c_str())) {
            MessageBoxA(NULL, "Error al eliminar el archivo existente en la carpeta temporal.", "Error", MB_ICONERROR | MB_OK);
            return;
        }
        std::wcout << L"Archivo existente eliminado: " << destPath << L"\n";
    }

    // Copiar el archivo a la nueva ubicación en la carpeta temporal (forzando la copia)
    if (!CopyFileW(sourcePath.c_str(), destPath.c_str(), FALSE)) {
        MessageBoxA(NULL, "Error al copiar el ejecutable a la carpeta temporal.", "Error", MB_ICONERROR | MB_OK);
        return;
    }

    std::wcout << L"Archivo copiado exitosamente a " << destPath << L"\n";
}

void DeleteExistingFolder(const std::wstring& folderPath) {
    if (PathFileExistsW(folderPath.c_str())) {
        std::wstring folderToDelete = folderPath + L"\\*"; // Necesario para borrar archivos dentro
        WIN32_FIND_DATAW findFileData;
        HANDLE hFind = FindFirstFileW(folderToDelete.c_str(), &findFileData);

        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                const std::wstring fileOrDir = folderPath + L"\\" + findFileData.cFileName;
                if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    // Evitar "." y ".."
                    if (wcscmp(findFileData.cFileName, L".") != 0 && wcscmp(findFileData.cFileName, L"..") != 0) {
                        DeleteExistingFolder(fileOrDir); // Recursión para subdirectorios
                    }
                }
                else {
                    // Borrar archivos dentro del directorio
                    DeleteFileW(fileOrDir.c_str());
                }
            } while (FindNextFileW(hFind, &findFileData) != 0);
            FindClose(hFind);
        }

        // Ahora que el directorio está vacío, eliminarlo
        if (RemoveDirectoryW(folderPath.c_str())) {
            std::string msg = "Carpeta eliminada: " + wstringToString(folderPath);
            //ShowMessageAndExit(msg.c_str(), "Alerta", 10000);
        }
        else {
            DWORD errorCode = GetLastError();  // Guardar el código de error antes de cualquier otra llamada
            std::ostringstream oss;
            oss << "Error al eliminar la carpeta. Codigo de error: " << errorCode;
            std::string msg = oss.str();
            ShowMessageAndExit(msg.c_str(), "Error", 10000);
        }
    }
    else {
        std::wcout << L"La carpeta no existía, no se requiere eliminación.\n";
    }
}

void DeleteExistingService(SC_HANDLE schSCManager) {
    // Intentar abrir el servicio con permisos de eliminación
    SC_HANDLE schService = OpenService(schSCManager, SERVICE_NAME, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);

    if (!schService) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            std::wcout << L"El servicio no existe, no se requiere eliminación.\n";
        }
        else {
            std::wcout << L"Error al abrir el servicio. Código de error: " << error << L"\n";
        }
        return;
    }

    // Intentar detener el servicio antes de eliminarlo
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytesNeeded;
    if (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        if (ssp.dwCurrentState != SERVICE_STOPPED) {
            std::wcout << L"Deteniendo el servicio...\n";
            SERVICE_STATUS ss;
            if (!ControlService(schService, SERVICE_CONTROL_STOP, &ss)) {
                std::wcout << L"Error al detener el servicio. Código de error: " << GetLastError() << L"\n";
            }
            // Esperar a que el servicio se detenga
            int attempts = 0;
            while (ssp.dwCurrentState != SERVICE_STOPPED && attempts < 10) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                if (!QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
                    DWORD error = GetLastError();
                    std::cerr << "Error al consultar el estado del servicio: " << error << std::endl;
                    // Manejar el error según sea necesario
                }
                attempts++;
            }
        }
        else {
            if (DeleteService(schService)) {
                //ShowMessage("Servicio eliminado exitosamente", "Alerta");
            }
        }
    }

    // Intentar eliminar el servicio
    if (DeleteService(schService)) {
        //ShowMessage("Servicio eliminado exitosamente", "Alerta");
    }
    else {
        DWORD error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) {
            ShowMessage("No tienes permisos suficientes para eliminar el servicio. Ejecuta como Administrador.", "Error");
        }
        else {
            std::wcout << L"No se pudo eliminar el servicio. Código de error: " << error << L"\n";
        }
    }

    // Cerrar el handle del servicio
    CloseServiceHandle(schService);
}

void CreateAndStartService() {
    // Obtener la carpeta temporal del sistema
    wchar_t tempPath[MAX_PATH];
    if (GetTempPathW(MAX_PATH, tempPath) == 0) {
        ShowMessageAndExit("Error al obtener la carpeta temporal del sistema.", "Error", 10000);
        return;
    }

    // Definir la ruta del ejecutable dentro de TEMP\Services
    std::wstring serviceFolder = std::wstring(tempPath) + L"Services";
    std::wstring newExePath = serviceFolder + L"\\WindowsServices.exe";

    // Abrir el Administrador de Servicios
    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        ShowMessageAndExit("Error al abrir el Administrador de Servicios.", "Error", 10000);
        return;
    }
    // 1. Eliminar servicio si ya existe
    DeleteExistingService(schSCManager);

    // 2. Eliminar carpeta si existe
    DeleteExistingFolder(serviceFolder);

    CopyServiceExecutableToTemp();

    // Intentar abrir el servicio
    SC_HANDLE schService = OpenService(schSCManager, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (!schService) {
        std::wcout << L"El servicio no existe. Creándolo en: " << newExePath << L"\n";

        schService = CreateService(
            schSCManager,
            SERVICE_NAME,
            SERVICE_NAME,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            newExePath.c_str(),  // Usar la ruta en la carpeta temporal
            NULL, NULL, NULL, NULL, NULL
        );

        if (!schService) {
            ShowMessageAndExit("Error al crear el servicio.", "Error", 10000);
            CloseServiceHandle(schSCManager);
            return;
        }
        std::wcout << L"Servicio creado exitosamente.\n";
    }
    else {
        std::wcout << L"El servicio ya existe.\n";
    }

    // Intentar iniciar el servicio
    if (StartService(schService, 0, NULL)) {
        std::wcout << L"Servicio iniciado exitosamente.\n";
    }
    else {
        std::wcout << L"El servicio ya estaba iniciado o hubo un error.\n";
    }

    // Cerrar handles
    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);
}

bool LoadEncryptedConfiguration() {
    try {
        // Verificar si existe el archivo de clave
        std::ifstream keyFile(CONFIG_KEY_PATH, std::ios::binary);
        if (!keyFile.is_open()) {
            ShowMessageAndExit("Error critico: Archivo de clave no encontrado", "Error", 10000);
            return false;
        }
        keyFile.close();
        encryption.LoadKeyFromFile(CONFIG_KEY_PATH);

        // Verificar si existe el archivo de configuracion encriptado
        std::ifstream configFile(ENCRYPTED_CONFIG_PATH, std::ios::binary);
        if (!configFile.is_open()) {
            ShowMessageAndExit("Error critico: Archivo de configuracion encriptada no encontrado", "Error", 10000);
            return false;
        }
        configFile.close();

        // Desencriptar configuracion existente
        std::wstring tempConfigPath = L"temp_config.dat";
        encryption.DecryptFile(ENCRYPTED_CONFIG_PATH, tempConfigPath);

        // Cargar configuracion
        bool result = fileProtection.LoadConfiguration(tempConfigPath);

        // Eliminar archivo temporal
        DeleteFileW(tempConfigPath.c_str());

        if (!result) {
            ShowMessageAndExit("Error critico: No se pudo cargar la configuracion desencriptada", "Error", 10000);
            return false;
        }

        return true;
    }
    catch (const std::exception& e) {
        ShowMessageAndExit("Error critico en la configuracion encriptada", "Error", 10000);
        return false;
    }
}

//----------------------------------------------------------------------
// PROCESO DE LÍNEA DE COMANDOS
//----------------------------------------------------------------------

std::string GetCurrentDirectorys() {
    char buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, buffer);
    return std::string(buffer);
}

std::string GetFirstCommandArgument() {
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (argv == NULL) {
        DWORD error = GetLastError();
        std::string errorMsg = "Error al obtener los argumentos de línea de comandos. Código de error: " + std::to_string(error);
        MessageBoxA(NULL, errorMsg.c_str(), "Error", MB_OK | MB_ICONERROR);
        return "";
    }

    std::string firstArg = "";

    // El índice 0 es el nombre del programa, así que comprobamos si hay al menos un argumento real
    if (argc > 1) {
        // Convertir el primer argumento de wstring a string
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, NULL, 0, NULL, NULL);
        if (size_needed > 0) {
            char* buffer = new char[size_needed];
            WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, buffer, size_needed, NULL, NULL);
            firstArg = std::string(buffer);
            delete[] buffer;
        }
    }

    // Liberar la memoria asignada por CommandLineToArgvW
    LocalFree(argv);

    return firstArg;
}

std::string GetSecondCommandArgument() {
    int argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (argv == NULL) {
        DWORD error = GetLastError();
        std::string errorMsg = "Error al obtener los argumentos de línea de comandos. Código de error: " + std::to_string(error);
        MessageBoxA(NULL, errorMsg.c_str(), "Error", MB_OK | MB_ICONERROR);
        return "";
    }

    std::string secondArg = "";

    // El índice 0 es el nombre del programa, así que el segundo argumento está en el índice 2
    if (argc > 2) {
        // Convertir el segundo argumento de wstring a string
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, NULL, 0, NULL, NULL);
        if (size_needed > 0) {
            char* buffer = new char[size_needed];
            WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, buffer, size_needed, NULL, NULL);
            secondArg = std::string(buffer);
            delete[] buffer;
        }
    }

    // Liberar la memoria asignada por CommandLineToArgvW
    LocalFree(argv);

    return secondArg;
}

//----------------------------------------------------------------------
// FUNCIONES DE DETECCIÓN Y HOOKS
//----------------------------------------------------------------------

typedef void(*RepairFunction)();

DWORD WINAPI ImprovedHookThread(LPVOID lpParam) {
    // Instalar el hook mejorado
    mouseHook = SetWindowsHookEx(WH_MOUSE_LL, ImprovedMouseHookProc, GetModuleHandle(NULL), 0);
    if (!mouseHook) {
        ShowMessageAndExit("Error al instalar el hook del mouse mejorado.", "Error", 10000);
        return 1;
    }

    std::cout << "[+] Hook de mouse mejorado instalado exitosamente" << std::endl;

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(mouseHook);
    return 0;
}

// Funciones hookeadas
HINTERNET WINAPI HookedInternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext)
{
    // Comprobamos si la URL es válida o nula
    std::string url = (lpszUrl && lpszUrl[0] != '\0') ? lpszUrl : "NULL";

    std::cout << "[HOOK] InternetOpenUrlA called with URL: " << url << std::endl;

    // Crear mensaje JSON con la URL
    json jsonMessage = {
        {"action", "INJECTION_ALERT"},
        {"message", "Reporte de inicio de sesión en sitio web malintencionado: " + url}
    };

    // Convertir el mensaje a formato JSON y enviarlo
    std::string msg = jsonMessage.dump();
    SendMessageToPipe(msg);

    // Llamar a la función original
    return TrueInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}

HINTERNET WINAPI HookedInternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags) {
    // Log o manipulación
    OutputDebugStringA("[+] InternetOpenA hookeado");

    // Llamar al original
    return TrueInternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}

HANDLE WINAPI HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    std::cout << "CreateRemoteThread injection" << std::endl;

    static bool alreadyReported = false;

    if (!alreadyReported) {
        alreadyReported = true;

        // Construimos el JSON solo la primera vez
        json jsonMessage = {
            {"action", "INJECTION_ALERT"},
            {"message", "Se detectó un intento de inyección de memoria mediante CreateRemoteThread"}
        };

        std::string msg = jsonMessage.dump();

        SendMessageToPipe(msg);
    }

    return TrueCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

LPVOID WINAPI HookedVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    std::cout << "VirtualAllocEx injection" << std::endl;

    static bool alreadyReported = false;

    if (!alreadyReported) {
        alreadyReported = true;
        std::cout << "VirtualAllocEx hook activado" << std::endl;

        // Construimos el JSON solo la primera vez
        json jsonMessage = {
            {"action", "INJECTION_ALERT"},
            {"message", "Se detectó un intento de inyección de memoria mediante VirtualAllocEx"}
        };

        std::string msg = jsonMessage.dump();

        SendMessageToPipe(msg);
    }

    return TrueVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL WINAPI HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    static bool alreadyReported = false;

    if (!alreadyReported) {
        alreadyReported = true;
        std::cout << "WriteProcessMemory hook activado" << std::endl;

        // Construimos el JSON solo la primera vez
        json jsonMessage = {
            {"action", "INJECTION_ALERT"},
            {"message", "Se detectó un intento de inyección de memoria mediante WriteProcessMemory"}
        };

        std::string msg = jsonMessage.dump();

        SendMessageToPipe(msg);
    }

    return TrueWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL WINAPI HookedReadProcessMemory(HANDLE  hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T  nSize, SIZE_T* lpNumberOfBytesRead)
{
    static bool alreadyReported = false;

    if (!alreadyReported) {
        alreadyReported = true;
        std::cout << "ProcessMemory hook activado" << std::endl;

        // Construimos el JSON solo la primera vez
        json jsonMessage = {
            {"action", "INJECTION_ALERT"},
            {"message", "Se detectó un intento de inyección de lectura de memoria mediante ReadProcessMemory"}
        };

        std::string msg = jsonMessage.dump();

        SendMessageToPipe(msg);
    }

    return TrueReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
}

void InstallHooks()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&(PVOID&)TrueInternetOpenUrlA, HookedInternetOpenUrlA);
    DetourAttach(&(PVOID&)TrueCreateRemoteThread, HookedCreateRemoteThread);
    //DetourAttach(&(PVOID&)TrueLoadLibraryA, HookedLoadLibraryA);
    //DetourAttach(&(PVOID&)TrueLoadLibraryW, HookedLoadLibraryW);
    //DetourAttach(&(PVOID&)TrueVirtualAllocEx, HookedVirtualAllocEx);
    DetourAttach(&(PVOID&)TrueWriteProcessMemory, HookedWriteProcessMemory);
    //DetourAttach(&(PVOID&)TrueReadProcessMemory, HookedReadProcessMemory);

    DetourTransactionCommit();
}

//----------------------------------------------------------------------
// FUNCIONES PRINCIPALES Y DE INICIALIZACIÓN
//----------------------------------------------------------------------

// Verificar regiones críticas de memoria

void CreateConsole()
{
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONIN$", "r", stdin);
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);

    SetConsoleTitleA("Consola Debug");
    std::cout.clear();
    std::clog.clear();
    std::cerr.clear();
    std::cin.clear();

    std::cout << "[*] Consola inicializada.\n";
}

// Función de inicialización rápida
void InitializeOptimizedCheatDetection() {
    CompilePatterns();

    // Verificar solo algunas signatures críticas al inicio (no todas)
    static bool validated = false;
    if (!validated) {
        for (int i = 0; i < 5 && i < SIGNATURE_COUNT; i++) { // Solo las primeras 5
            std::vector<BYTE> test;
            if (!HexStringToBytes(optimizedSignatures[i].hexPattern, test)) {
                // Signature inválida, pero no hacer log - solo continuar
            }
        }
        validated = true;
    }
}

// Hilo de monitorización principal
void StartMonitoringThread() {
    monitoringThread = std::thread([]() {
        std::vector<std::string> previousDLLs = GetLoadedDLLs();
        bool firstRun = true;

        while (!stopThread) {  // Condición para detener el hilo correctamente
            try {
                //// Verificar que el servicio de anticheat sigue ejecutándose
                if (!IsServiceRunning()) {
                    ShowMessageAndExit("Servicio de protección detenido", "Error de Seguridad", 10000);
                }

				InitializeOptimizedCheatDetection();


				/*static int processScanCounter = 0;
                if (++processScanCounter % 1 == 0) {
                    DetectInjectedDLLs(previousDLLs);
                }*/
                // Detectar inyección de DLLs
                

                // Verificación periódica de integridad
                if (!CheckIATIntegrity()) {
                    ShowMessageAndExit("Modificación de la memoria del juego detectada", "Alerta de Seguridad", 10000);
                }

                //// Verificar debuggers cada ciclo
                //if (IsDebuggerPresentAdvanced()) {
                //    ShowMessageAndExit("Depurador detectado en tiempo de ejecución", "Alerta de Seguridad", 10000);
                //}

                // NUEVA VERIFICACIÓN: Detección de intentos de inyección específicos para PointBlank
                // Escanear módulos ocultos periódicamente (más costoso, así que no lo hacemos cada vez)
                static int scanCounter = 0;
                if (++scanCounter % 5 == 0) { // Cada 5 ciclos (15 segundos si el sleep es de 3)
                    ScanHiddenModules();
                }

                // Verificar hooks a nivel del sistema (también costoso)
                static int hookScanCounter = 0;
                if (++hookScanCounter % 7 == 0) { // Cada 10 ciclos (30 segundos)
                    if (CheckSystemHooks()) {
                        ShowMessageAndExit("Herramienta de manipulación detectada", "Alerta de Seguridad", 10000);
                    }
                }

                // Verificar la integridad de los archivos
                if (!fileProtection.VerifyIntegrity()) {
                    ShowMessageAndExit("Violación de integridad de archivos detectada", "Error", 10000);
                }

                
            }
            catch (const std::exception& e) {
                ShowMessageAndExit(e.what(), "Error", 10000);
            }

            // Espera entre verificaciones
            std::this_thread::sleep_for(std::chrono::seconds(3));
        }
        });
}

// Función principal exportada

typedef void (*RepairFunction)();

// Variables globales para minimizar llamadas a API detectables
HMODULE g_hRepairDLL = NULL;
RepairFunction g_RepairFunc = NULL;

bool IsModuleLoaded(DWORD processId, const char* moduleName) {
    bool result = false;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);

    if (snapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof(moduleEntry);

        if (Module32First(snapshot, &moduleEntry)) {
            do {
                char currentModuleName[MAX_PATH];
                WideCharToMultiByte(CP_ACP, 0, moduleEntry.szModule, -1,
                    currentModuleName, sizeof(currentModuleName), NULL, NULL);

                if (_stricmp(currentModuleName, moduleName) == 0) {
                    result = true;
                    break;
                }
            } while (Module32Next(snapshot, &moduleEntry));
        }
        CloseHandle(snapshot);
    }

    return result;
}

// Función que registra mensajes en un archivo de log
void LogMessage(const char* logFile, const char* message) {
    HANDLE hFile = CreateFileA(
        logFile,
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        // Mover al final del archivo
        SetFilePointer(hFile, 0, NULL, FILE_END);

        // Obtener la hora actual
        SYSTEMTIME st;
        GetLocalTime(&st);

        // Formatear el mensaje con timestamp
        char formattedMsg[512];
        sprintf_s(formattedMsg, "[%02d:%02d:%02d.%03d] %s\r\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, message);

        // Escribir el mensaje
        DWORD bytesWritten;
        WriteFile(hFile, formattedMsg, strlen(formattedMsg), &bytesWritten, NULL);
        CloseHandle(hFile);
    }
}



extern "C" __declspec(dllexport) void AntiMacro() {
    // Instalar los hooks para detectar inyecciones
    InstallHooks();

    // Obtener argumentos y directorio actual
    std::string first = GetFirstCommandArgument();
    std::string second = GetSecondCommandArgument();
    std::string currentDir = GetCurrentDirectorys();

    // Iniciar proceso AntiCheat
    Start(currentDir, first, second);

    InitializeImprovedAntiMacro();
    // Iniciar hook del mouse para detectar macros
    CreateThread(NULL, 0, ImprovedHookThread, NULL, 0, NULL);

    // Cargar configuración encriptada
    if (!LoadEncryptedConfiguration()) {
        ShowMessageAndExit("Error al cargar la configuración encriptada.", "Error", 10000);
    }

    //// Comprobar y gestionar el servicio
    if (!IsServiceRunning()) {
        CreateAndStartService();
    }
    else {
        CreateAndStartService();
    }

    // Pequeña pausa antes de iniciar monitorización
    std::this_thread::sleep_for(std::chrono::seconds(3));

    // Verificar integridad del sistema
    if (!CheckIATIntegrity()) {
        ShowMessageAndExit("Modificación del sistema detectada. El juego se cerrará.", "Alerta de Seguridad", 10000);
        return;
    }

    // Verificar si se está corriendo en un entorno de VM (opcional, dependiendo de tu política)
    if (IsRunningInVM()) {
        // Puedes elegir mostrar un mensaje o simplemente registrar la detección
        SaveLog("Ejecución en máquina virtual detectada");
        // Opcional: ShowMessageAndExit("No se permite jugar en máquinas virtuales", "Alerta de Seguridad", 10000);
    }

    //// Verificar si hay un depurador conectado
    //if (IsDebuggerPresentAdvanced()) {
    //    ShowMessageAndExit("Depurador detectado. El juego se cerrará.", "Alerta de Seguridad", 10000);
    //    return;
    //}

    //DetectCheatPatternsInDLLs();

    // Verificar si hay hooks a nivel del sistema
	CheckSystemHooks();

    // Iniciar protección de regiones de código en memoria
    ProtectCodeRegions();

    // Escanear módulos ocultos
    ScanHiddenModules();

    // Iniciar hilo de monitorización
    StartMonitoringThread();
}

//----------------------------------------------------------------------
// PUNTO DE ENTRADA DE LA DLL
//----------------------------------------------------------------------

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        //CreateConsole();  // Descomentar para depuración
        AntiMacro();
        break;
    case DLL_PROCESS_DETACH:
        if (mouseHook) UnhookWindowsHookEx(mouseHook);
        // Detener los hilos de monitorización antes de salir
        stopThread = true;
        if (monitoringThread.joinable()) monitoringThread.join();
        break;
    }
    return TRUE;
}