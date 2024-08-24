#ifndef CLIENT_VIEW_QTVIEW_LOGINDIALOG_H
#define CLIENT_VIEW_QTVIEW_LOGINDIALOG_H

#include <QDialog>
#include <QLineEdit>

namespace view {

class LoginDialog : public QDialog {
public:
    explicit LoginDialog(QWidget *parent = nullptr);
    static QStringList getStrings(QWidget *parent, bool *ok = nullptr);
private:
    QList<QLineEdit*> fields;
};

};

#endif // CLIENT_VIEW_QTVIEW_LOGINDIALOG_H