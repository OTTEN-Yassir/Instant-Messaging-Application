#include <iostream>
#include "model/core.h"
#include "view/QTView/QTView.h"

int main(int argc, char** argv){
    if(argc != 3){
        std::cerr << "Usage: " << argv[0] << " <host> <port>\n";
        return 1;
    }

    model::Core core{argv[1], std::stoi(argv[2])};
    view::QTView view{argc, argv, &core};
    view.run();
}
