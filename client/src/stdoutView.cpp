#include "../view/stdoutView.h"

namespace view {

void StdoutView::run() {
    std::string input;
    std::cout << "Enter your username: ";
    std::cin >> input;
    core->generateAndSendKey(input);

    bool running{true};
    while (running) {
        std::cin >> input;
        if (input == "exit")
            running = false;
        else if (input == "list") {
            core->fetchMessages();
        }
        else {
            core->sendMessage(input, "");
        }
    }
}

void StdoutView::update(const nvs::Subject * subject, const std::string& element) {
    const model::Core *const_core = static_cast<const model::Core *>(subject);

    if(element == "MESSAGES") {
        messages_buffer.clear();
        for(const auto& message : const_core->getMessages())
            messages_buffer += message + "\n";
    }

    std::cout << messages_buffer << std::endl;
}

}; // namespace view