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
    AddYaraRule("AUTOCLICKER",
        "import \"pe\"\n"
        "rule AUTOCLICKER {\n"
        "    strings:\n"
        "        $a1 = \"AutoClicker\" nocase ascii wide\n"
        "        $a2 = \"Click Interval\" nocase ascii wide\n"
        "        $a3 = \"Start Clicking\" nocase ascii wide\n"
        "        $a4 = \"Stop Clicking\" nocase ascii wide\n"
        "        $a6 = \"mouse_event\" nocase ascii wide\n"
        "    condition:\n"
        "        2 of them\n"
        "}\n"
    );

    AddYaraRule("IMPORTS",
        "rule IMPORTS {\n"
        "    condition:\n"
        "        pe.imports(\"user32.dll\", \"mouse_event\") and\n"
        "        pe.imports(\"user32.dll\", \"GetAsyncKeyState\") and\n"
        "        pe.imports(\"kernel32.dll\", \"Sleep\")\n"
        "}\n"
    );

    AddYaraRule("CSHARP",
        "rule CSHARP {\n"
        "    strings:\n"
        "        $dotnet1 = \"mscorlib\" ascii wide\n"
        "        $dotnet2 = \"System.Windows.Forms\" ascii wide\n"
        "        $dotnet3 = \"System.Threading\" ascii wide\n"
        "        $dotnet4 = \"System.Reflection\" ascii wide\n"
        "        $dotnet5 = \"System.Runtime.InteropServices\" ascii wide\n"
        "        $input1 = \"SendInput\" ascii wide\n"
        "        $input2 = \"mouse_event\" ascii wide\n"
        "        $input3 = \"SetCursorPos\" ascii wide\n"
        "        $input4 = \"keybd_event\" ascii wide\n"
        "        $click1 = \"AutoClicker\" ascii wide\n"
        "        $click2 = \"Clicker\" ascii wide\n"
        "        $click3 = \"MouseClicker\" ascii wide\n"
        "        $click4 = \"ClickInterval\" ascii wide\n"
        "        $click5 = \"StartClicking\" ascii wide\n"
        "        $click6 = \"ClicksPerSecond\" ascii wide\n"
        "    condition:\n"
        "        (1 of($dotnet*)) and (1 of($input*)) and (1 of($click*))\n"
        "}\n"
    );

    AddYaraRule("CHEAT",
        "rule CHEAT {\n"
        "    strings:\n"
        "        $a = \"penis.dll\" nocase ascii wide\n"
        "        $b = \"[!] Github: https://github.com/JohnXina-spec\" nocase ascii wide\n"
        "        $c = \".vapeclientT\" nocase ascii wide\n"
        "        $d = \"(JLcn/gov/vape/util/jvmti/ClassLoadHook;)I\" nocase ascii wide\n"
        "        $e = \"net.ccbluex.liquidbounce.UT\" nocase ascii wide\n"
        "        $f = \"nick.AugustusClassLoader.class\" nocase ascii wide\n"
        "        $g = \"com.riseclient.Main.class\" nocase ascii wide\n"
        "        $h = \"slinky_library.dll\" nocase ascii wide\n"
        "        $i = \"assets.minecraft.haru.img.clickgui.PK\" nocase ascii wide\n"
        "        $j = \"assets.minecraft.sakura.sound.welcome.mp3\" nocase ascii wide\n"
        "        $k = \"VROOMCLICKER\" nocase ascii wide\n"
        "        $n = \"www.koid.es\" nocase ascii wide\n"
        "        $o = \"vape.gg\" nocase ascii wide\n"
        "        $q = \"DopeClicker\" nocase ascii wide\n"
        "        $s = \"Cracked by Kangaroo\" nocase ascii wide\n"
        "        $t = \"Sapphire LITE Clicker\" nocase ascii wide\n"
        "        $w = \"dream-injector\" nocase ascii wide\n"
        "        $x = \"Exodus.codes\" nocase ascii wide\n"
        "        $y = \"slinky.gg\" nocase ascii wide\n"
        "        $z = \"[!] Failed to find Vape jar\" nocase ascii wide\n"
        "        $aa = \"Vape Launcher\" nocase ascii wide\n"
        "        $ac = \"String Cleaner\" nocase ascii wide\n"
        "        $ad = \"Open Minecraft, then try again.\" nocase ascii wide\n"
        "        $af = \"PE Injector\" nocase ascii wide\n"
        "        $ah = \"starlight v1.0\" nocase ascii wide\n"
        "        $ai = \"Striker.exe\" nocase ascii wide\n"
        "        $aj = \"Monolith Lite\" nocase ascii wide\n"
        "        $ak = \"B.fagg0t0\" nocase ascii wide\n"
        "        $al = \"B.fag0\" nocase ascii wide\n"
        "        $ap = \"UNICORN CLIENT\" nocase ascii wide\n"
        "        $aq = \"Adding delay to Minecraft\" nocase ascii wide\n"
        "        $ar = \"rightClickChk.BackgroundImage\" nocase ascii wide\n"
        "        $as = \"UwU Client\" nocase ascii wide\n"
        "        $at = \"lithiumclient.wtf\" nocase ascii wide\n"
        "        $au = \"vape.g\" nocase ascii wide\n"
        "        $av = \"S3t 4ut0C1ick3r t0ggLe key\" nocase ascii wide\n"
        "        $aw = \"RECOVERYCLICKER\" nocase ascii wide\n"
        "    condition:\n"
        "        any of them\n"
        "}\n"
    );

    AddYaraRule("HIGH_ENTROPY",
        "import \"math\"\n"
        "rule HIGH_ENTROPY {\n"
        "    condition:\n"
        "        math.entropy(0, filesize) > 7.0\n"
        "}\n"
    );

    AddYaraRule("HIGH_ENTROPY_SECTION",
        "import \"pe\"\n"
        "import \"math\"\n"
        "rule HIGH_ENTROPY_SECTION {\n"
        "    condition:\n"
        "        for any section in pe.sections : (\n"
        "            math.entropy(section.raw_data_offset, section.raw_data_size) > 7.0\n"
        "        )\n"
        "}\n"
    );
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
