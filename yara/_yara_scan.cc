#pragma once
#include <string>
#include <vector>
#include <cstdio>
#include <mutex>
#include <yara.h>
#include <filesystem>

struct YaraRuleDef {
    std::string name;
    std::string source;
};

std::vector<YaraRuleDef> globalRules;
YR_RULES* compiledRules = nullptr;
std::mutex yaraMutex;

void AddYaraRule(const std::string& name, const std::string& ruleSource) {
    globalRules.push_back({ name, ruleSource });
}

void InitGenericRules() {
    AddYaraRule("STRINGS", R"(
import "pe"
rule STRINGS {
    strings:
        $a1 = "AutoClicker" nocase ascii wide
        $a2 = "Click Interval" nocase ascii wide
        $a3 = "Start Clicking" nocase ascii wide
        $a4 = "Stop Clicking" nocase ascii wide
        $a6 = "mouse_event" nocase ascii wide
    condition:
        3 of them
}
)");

    AddYaraRule("IMPORTS", R"(

rule IMPORTS {
    condition:
        pe.imports("user32.dll", "mouse_event") and
        pe.imports("user32.dll", "GetAsyncKeyState") and
        pe.imports("kernel32.dll", "Sleep")
}
)");

    AddYaraRule("CSHARP", R"(

rule CSHARP {

        strings:
        $dotnet1 = "mscorlib" ascii wide
        $dotnet2 = "System.Windows.Forms" ascii wide
        $dotnet3 = "System.Threading" ascii wide
        $dotnet4 = "System.Reflection" ascii wide
        $dotnet5 = "System.Runtime.InteropServices" ascii wide

        $input1 = "SendInput" ascii wide
        $input2 = "mouse_event" ascii wide
        $input3 = "SetCursorPos" ascii wide
        $input4 = "keybd_event" ascii wide

        $click1 = "AutoClicker" ascii wide
        $click2 = "Clicker" ascii wide
        $click3 = "MouseClicker" ascii wide
        $click4 = "ClickInterval" ascii wide
        $click5 = "StartClicking" ascii wide
        $click6 = "ClicksPerSecond" ascii wide

        condition :
            (1 of($dotnet*)) and (1 of($input*)) and (1 of($click*))
}
)");

    AddYaraRule("CHEAT", R"(
rule CHEAT {
    strings:
          $a = "penis.dll" nocase ascii wide
          $b = "[!] Github: https://github.com/JohnXina-spec" nocase ascii wide 
          $c = ".vapeclientT" nocase ascii wide 
          $d = "(JLcn/gov/vape/util/jvmti/ClassLoadHook;)I" nocase ascii wide
          $e = "net/ccbluex/liquidbounce/UT" nocase ascii wide 
          $f = "nick/AugustusClassLoader.class" nocase ascii wide 
          $g = "com/riseclient/Main.class" nocase ascii wide 
          $h = "slinky_library.dll" nocase ascii wide
          $i = "assets/minecraft/haru/img/clickgui/PK" nocase ascii wide 
          $j = "assets/minecraft/sakura/sound/welcome.mp3" nocase ascii wide 
          $k = "VROOMCLICKER" nocase ascii wide
          $l = "C:\\Users\\hyeox\\Desktop\\imgui-master\\examples\\example_win32_directx9\\Release\\icetea_dx9_final.pdb" nocase ascii wide
          $m = "Set autoclicker toggle key (It's can be a mouse button) -> " nocase ascii wide 
          $n = "www.koid.es" nocase ascii wide 
          $o = "vape.gg" nocase ascii wide
          $p = "C:\\Users\\DeathZ\\source\\repos\\StarDLL\\x64\\Release\\MoonDLL.pdb" nocase ascii wide
          $q = "DopeClicker" nocase ascii wide
          $r = "C:\\Users\\mella\\source\\repos\\Fox v2\\x64\\Release\\Fox.pdb" nocase ascii wide
          $s = "Cracked by Kangaroo" nocase ascii wide
          $t = "Sapphire LITE Clicker" nocase ascii wide
          $w = "dream-injector" nocase ascii wide
          $x = "Exodus.codes" nocase ascii wide
          $y = "slinky.gg" nocase ascii wide
          $z = "[!] Failed to find Vape jar" nocase ascii wide
          $aa = "Vape Launcher" nocase ascii wide
          $ab = "C:\\Users\\PC\\Desktop\\Cleaner-main\\obj\\x64\\Release\\WindowsFormsApp3.pdb" nocase ascii wide
          $ac = "String Cleaner" nocase ascii wide
          $ad = "Open Minecraft, then try again." nocase ascii wide
          $af = "PE Injector" nocase ascii wide
          $ah = "starlight v1.0" nocase ascii wide
          $ai = "Striker.exe" nocase ascii wide
          $aj = "Monolith Lite" nocase ascii wide
          $ak = "B.fagg0t0" nocase ascii wide
          $al = "B.fag0" nocase ascii wide
          $an = "C:\\Users\\Daniel\\Desktop\\client-top\\x64\\Release\\top-external.pdb" nocase ascii wide
          $ao = "C:\\Users\\Daniel\\Desktop\\client-top\\x64\\Release\\top-internal.pdb" nocase ascii wide
          $ap = "UNICORN CLIENT" nocase ascii wide
          $aq = "Adding delay to Minecraft" nocase ascii wide
          $ar = "rightClickChk.BackgroundImage" nocase ascii wide
          $as = "UwU Client" nocase ascii wide
          $at = "lithiumclient.wtf" nocase ascii wide

    condition:
       any of them
}
)");
}

int YaraMatchCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* matchedRule = (YR_RULE*)message_data;
        std::vector<std::string>* matches = (std::vector<std::string>*)user_data;
        matches->push_back(matchedRule->identifier);
    }
    return CALLBACK_CONTINUE;
}

void YaraCompilerError(int level, const char* file, int line, const YR_RULE* rule, const char* msg, void* user_data) {
    fprintf(stderr, "[YARA ERROR] %s:%d - %s\n", file ? file : "N/A", line, msg);
}

bool InitYara() {
    if (yr_initialize() != ERROR_SUCCESS) return false;

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        yr_finalize();
        return false;
    }

    yr_compiler_set_callback(compiler, YaraCompilerError, nullptr);

    for (const auto& rule : globalRules) {
        if (yr_compiler_add_string(compiler, rule.source.c_str(), nullptr) != 0) {
            yr_compiler_destroy(compiler);
            yr_finalize();
            return false;
        }
    }

    if (yr_compiler_get_rules(compiler, &compiledRules) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        yr_finalize();
        return false;
    }

    yr_compiler_destroy(compiler);
    return true;
}

void FinalizeYara() {
    if (compiledRules) {
        yr_rules_destroy(compiledRules);
        compiledRules = nullptr;
    }
    yr_finalize();
}

bool FastScanFile(const std::string& filePath, std::vector<std::string>& matchedRules) {
    if (!compiledRules)
        return false;

    matchedRules.clear();

    return (yr_rules_scan_file(compiledRules, filePath.c_str(), SCAN_FLAGS_FAST_MODE, YaraMatchCallback, &matchedRules, 0) == ERROR_SUCCESS)
        && !matchedRules.empty();
}