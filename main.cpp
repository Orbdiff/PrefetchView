#include <iostream>
#include <string>

int main() {
    std::string greeting = "こんにちは、世界！";
    std::string question = "お名前は何ですか？";
    std::string name = "田中太郎";
    std::string response = "よろしくお願いします。";

    std::cout << greeting << std::endl;
    std::cout << question << std::endl;
    std::cout << "私の名前は" << name << "です。" << std::endl;
    std::cout << response << std::endl;

    return 0;
}