#pragma once

#include <string>
#include <vector>
#include <mutex>
#include <yara.h>
#include <filesystem>

struct YaraRuleDef {
    std::string name;
    std::string source;
};

extern std::vector<YaraRuleDef> globalRules;
extern YR_RULES* compiledRules;
extern std::mutex yaraMutex;

void AddYaraRule(const std::string& name, const std::string& ruleSource);
void InitGenericRules();
int YaraMatchCallback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);
void YaraCompilerError(int level, const char* file, int line, const YR_RULE* rule, const char* msg, void* user_data);
bool InitYara();
void FinalizeYara();
bool FastScanFile(const std::string& filePath, std::vector<std::string>& matchedRules);
