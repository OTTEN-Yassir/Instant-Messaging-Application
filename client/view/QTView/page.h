#ifndef PAGE_H
#define PAGE_H

#include <QtWidgets>
#include "../../model/core.h"

namespace model { struct Message; };

namespace view {

class Page : public QWidget {
public:
     Page(model::Core *core, QWidget *parent = nullptr,int id=0);

     void updateMessages(const std::vector<model::Message> &messages);
private:
    model::Core *corePtr;
    QVBoxLayout *pageLayout;
    QScrollArea *scrollArea;
    QWidget *scrollWidget;
    QVBoxLayout *scrollLayout;
    QLabel *pageNumberLabel;
    QLineEdit *lineEdit;
    QHBoxLayout *lineSubmitLayout;
    QPushButton *submitButton, *addFileButton;

    void clearMessages();

};

};

#endif // PAGE_H
