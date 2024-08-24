#ifndef CLIENT_VIEW_H
#define CLIENT_VIEW_H

#include "../utils/observer.h"
#include "../model/core.h"

namespace view {

/**
 * @brief Abstract class to represent a view in the messaging application.
 */
class View : public nvs::Observer {
protected:
    model::Core *core;
public:
    /**
     * @brief Constructs a View object with the given Core instance.
     * @param core The Core instance.
     */
    View(model::Core *core) : core(core) {
        core->registerObserver(this);
    }

    /**
     * @brief Launches the view event loop.
     */
    virtual void run() = 0;
};

};

#endif // CLIENT_VIEW_H