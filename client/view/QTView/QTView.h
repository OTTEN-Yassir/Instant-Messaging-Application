#ifndef QTVIEW_H
#define QTVIEW_H

#include "../view.h"
#include "mainwindow.h"
#include "sideBar.h"
#include "page.h"
#include <QApplication>

namespace view {

class QTView : public View, public QApplication {
    QMainWindow mainWindow;
    QWidget *centralWidget;
    Page *chatPage;
    sideBar *sidebar;
public:
    QTView(int argc, char *argv[], model::Core *core);

    void run() override;

    void update(const nvs::Subject * subject, const std::string& element) override;
};

}; // namespace view

#endif // QTVIEW_H
