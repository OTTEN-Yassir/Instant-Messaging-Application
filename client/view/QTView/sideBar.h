#ifndef SIDEBAR_H
#define SIDEBAR_H

#include <QtWidgets>
#include "../../model/core.h"

namespace view {

class sideBar : public QWidget {
public:
    explicit sideBar(model::Core *core, QWidget *parent = nullptr);
    void updateContacts(const std::vector<std::string> &contacts, const std::string &selectedContact);
    void updateGroups(const std::vector<std::pair<int, std::string>> &groups, const std::string & selectedGroup);
private:
    model::Core *corePtr;
    QPushButton *newContactButton, *newGroupButton;
    QVBoxLayout *contactsLayout, *groupsLayout;

    void clearContacts();
    void clearGroups();
protected:
    void paintEvent(QPaintEvent *event) override;
};

}; // namespace view

#endif // SIDEBAR_H
