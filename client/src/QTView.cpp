#include "../view/QTView/mainwindow.h"
#include "../view/QTView/ui_mainwindow.h"
#include "../view/QTView/page.h"
#include "../view/QTView/sideBar.h"
#include "../view/QTView/QTView.h"
#include "../view/QTView/loginDialog.h"
#include <QVBoxLayout>
#include <QScrollArea>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QFormLayout>
#include "../model/message.h"

namespace view {

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

Page::Page(model::Core *core, QWidget *parent,int id)
    : QWidget(parent), pageLayout(new QVBoxLayout(this)), scrollArea(new QScrollArea(this)),
      scrollWidget(new QWidget(scrollArea)), scrollLayout(new QVBoxLayout(scrollWidget)),
      pageNumberLabel(new QLabel(scrollWidget)), lineEdit(new QLineEdit(this)),
      lineSubmitLayout(new QHBoxLayout), submitButton(new QPushButton("Submit", this)), addFileButton(new QPushButton("Add file", this)),
      corePtr{core}
    {

    scrollArea->setWidgetResizable(true); // Allow scroll area to resize widget
    scrollArea->setWidget(scrollWidget); // Set scroll widget to scroll area
    pageLayout->addWidget(scrollArea); // Add scroll area to page layout

    // Label to display page number
    scrollLayout->addWidget(pageNumberLabel); // Add page number at top of scroll area

    // LineEdit for user input
    pageLayout->addWidget(lineEdit); // Add line edit to page layout

    // Horizontal layout for line edit and submit button
    pageLayout->addLayout(lineSubmitLayout); // Add horizontal layout to page layout

    // Button to submit message
    lineSubmitLayout->addWidget(lineEdit); // Add line edit to horizontal layout
    lineSubmitLayout->addWidget(submitButton); // Add submit button to horizontal layout
    lineSubmitLayout->addWidget(addFileButton);
    
    // Connect button to slot for printing message
    QObject::connect(submitButton, &QPushButton::clicked, [&]() {
        if(lineEdit->text().isEmpty()) return;
        try {
            corePtr->sendMessage(lineEdit->text().toStdString());
        } catch (const std::runtime_error &e) {
            QMessageBox msgBox;
            msgBox.setText(e.what());
            msgBox.exec();
        }
        lineEdit->clear();
    });

    QObject::connect(addFileButton, &QPushButton::clicked, [&]() {
        QFileDialog dialog(this);
        dialog.setFileMode(QFileDialog::ExistingFile);
        QStringList fileNames;
        if (! dialog.exec()) return;

        fileNames = dialog.selectedFiles();\
        try {
            corePtr->sendFile(fileNames[0].toStdString());
        } catch (const std::runtime_error &e) {
            QMessageBox msgBox;
            msgBox.setText(e.what());
            msgBox.exec();
        }
    });

    setLayout(pageLayout);

}

void Page::updateMessages(const std::vector<model::Message> &messages) {
    clearMessages();
    for (const auto &message : messages) {
        QLabel *usernameLabel{new QLabel(QString::fromStdString(message.sender), scrollWidget)};
        QLabel *messageLabel = new QLabel(QString::fromStdString(message.content), scrollWidget);

        QWidget *hBoxWidget = new QWidget(scrollWidget);
        QHBoxLayout *hBoxLayout = new QHBoxLayout(hBoxWidget);
        hBoxWidget->setLayout(hBoxLayout);
        hBoxLayout->addWidget(messageLabel);

        if(message.type == model::MessageType::FILE) {
            auto downloadButton = new QPushButton("⤓", hBoxWidget);
            hBoxLayout->addWidget(downloadButton);
            connect(downloadButton, &QPushButton::clicked, [&, message]() {
                QMessageBox msgBox;
                try {
                    corePtr->downloadFile(message.remote_filename, message.content, message.decryption_key);
                    msgBox.setText("File downloaded successfully");
                } catch (const std::runtime_error &e) {
                    msgBox.setText(e.what());
                }
                msgBox.exec();
            });
        }
        
        
        if (message.sender == corePtr->getUsername()) {
            messageLabel->setStyleSheet("background-color: #ADD8E6; border: 1px solid #4682B4; border-radius: 5px; padding: 5px;");
            scrollLayout->addWidget(usernameLabel, 0, Qt::AlignRight); // Align QLabel to the left
            scrollLayout->addWidget(hBoxWidget, 0, Qt::AlignRight); // Align QLabel to the right
        } else {
            messageLabel->setStyleSheet("background-color: #4682B4; border: 1px solid #4682B4; border-radius: 5px; padding: 5px;");
            scrollLayout->addWidget(usernameLabel, 0, Qt::AlignLeft); // Align QLabel to the left
            scrollLayout->addWidget(hBoxWidget, 0, Qt::AlignLeft); // Align QLabel to the left
        }

        // Adjust frame size to match message size
        messageLabel->adjustSize();
    }
}

void Page::clearMessages() {
    QLayoutItem *child;
    while ((child = scrollLayout->takeAt(0)) != 0) {
        delete child->widget();
        delete child;
    }
}

sideBar::sideBar(model::Core *core, QWidget *parent) : corePtr(core), QWidget(parent), newContactButton{new QPushButton("+ Contact")}, newGroupButton{new QPushButton("+ Group")} {
    // setFixedWidth(100); // Set fixed width for sidebar
    setStyleSheet("background-color: lightblue;");

    QString buttonStyleSheet = "background-color: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #b3d9ff, stop:1 #80bfff);"
                               "border: 1px solid #005c99;"

                               "padding: 5px;";

    newContactButton->setStyleSheet(buttonStyleSheet);
    newGroupButton->setStyleSheet(buttonStyleSheet);

    // Create layout
    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->addStretch(); // Add stretchable space to push bottom button to the bottom
    
    auto contactsWidget = new QWidget(this);
    contactsLayout = new QVBoxLayout(contactsWidget);
    contactsWidget->setLayout(contactsLayout);

    auto groupsWidget = new QWidget(this);
    groupsLayout = new QVBoxLayout(groupsWidget);
    groupsWidget->setLayout(groupsLayout);

    auto hBoxWidget = new QWidget(this);
    auto hBoxLayout = new QHBoxLayout(hBoxWidget);
    hBoxWidget->setLayout(hBoxLayout);
    hBoxLayout->addWidget(newContactButton);
    hBoxLayout->addWidget(newGroupButton);

    layout->addWidget(new QLabel("Contacts"));
    layout->addWidget(contactsWidget);
    layout->addWidget(new QLabel("Groups"));
    layout->addWidget(groupsWidget);
    layout->addWidget(hBoxWidget);

    // Set margins and spacing
    layout->setContentsMargins(10, 10, 10, 10); // Set margins to create space from the borders
    layout->setSpacing(2); // No spacing between widgets
    QObject::connect(newContactButton, &QPushButton::clicked, [&]() {
        bool ok;
        QString text = QInputDialog::getText(
            this, 
            tr("New contact"),
            tr("User name:"), 
            QLineEdit::Normal,
            QDir::home().dirName(), 
            &ok
        );
        if(!ok) { return; }

        try {
            corePtr->addContact(text.toStdString());
        } catch (const std::runtime_error &e) {
            QMessageBox msgBox;
            msgBox.setText(e.what());
            msgBox.exec();
        }
    });
    QObject::connect(newGroupButton, &QPushButton::clicked, [&]() {
        bool ok;
        QString text = QInputDialog::getText(
            this, 
            tr("Create group"),
            tr("Group name:"), 
            QLineEdit::Normal,
            QDir::home().dirName(), 
            &ok
        );
        if(!ok) { return; }

        try {
            corePtr->createGroup(text.toStdString());
        } catch (const std::runtime_error &e) {
            QMessageBox msgBox;
            msgBox.setText(e.what());
            msgBox.exec();
        }
    });
    // Set layout to the sidebar
    setLayout(layout);
}
void sideBar::updateContacts(const std::vector<std::string> &contacts, const std::string &currentDestination) {
    clearContacts();
    for (const auto &contact : contacts) {
        QPushButton *button = new QPushButton(QString::fromStdString(contact));
        button->setStyleSheet("background-color: #ADD8E6; border: 1px solid #4682B4; border-radius: 5px; padding: 5px;");
        if(contact == currentDestination) {
            button->setStyleSheet("background-color: #4682B4; border: 1px solid #4682B4; border-radius: 5px; padding: 5px;");
        }
        contactsLayout->addWidget(button);
        QObject::connect(button, &QPushButton::clicked, [&, contact]() {
            try {
                corePtr->setDestination({model::DestType::DIRECT, contact});
            } catch(const std::runtime_error &e) {
                QMessageBox msgBox;
                msgBox.setText(e.what());
                msgBox.exec();
            }
        });
    }
}

void sideBar::updateGroups(const std::vector<std::pair<int, std::string>> &groups, const std::string& currentDestination) {
    clearGroups();
    for (const auto &group : groups) {
        auto hBoxWidget = new QWidget(this);
        auto hBoxLayout = new QHBoxLayout(hBoxWidget);
        hBoxWidget->setLayout(hBoxLayout);

        QPushButton *groupButton = new QPushButton(QString::fromStdString(group.second));
        QPushButton *addUserButton = new QPushButton("+");

        addUserButton->setFixedWidth(20);
        addUserButton->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);

        groupButton->setStyleSheet("background-color: #ADD8E6; border: 1px solid #4682B4; border-radius: 5px; padding: 5px;");
        addUserButton->setStyleSheet("background-color: #ADD8E6; border: 1px solid #4682B4; border-radius: 5px; padding: 5px;");
        if(std::to_string(group.first) == currentDestination) {
            groupButton->setStyleSheet("background-color: #4682B4; border: 1px solid #4682B4; border-radius: 5px; padding: 5px;");
        }
        hBoxLayout->addWidget(groupButton);
        hBoxLayout->addWidget(addUserButton);

        groupsLayout->addWidget(hBoxWidget);
        QObject::connect(groupButton, &QPushButton::clicked, [&, group]() {
            try {
                corePtr->setDestination({model::DestType::GROUP, std::to_string(group.first)});
            } catch(const std::runtime_error &e) {
                QMessageBox msgBox;
                msgBox.setText(e.what());
                msgBox.exec();
            }
        });
        QObject::connect(addUserButton, &QPushButton::clicked, [&, group]() {
            bool ok;
            QString text = QInputDialog::getText(
                this, 
                tr("Add user to group"),
                tr("User name:"), 
                QLineEdit::Normal,
                QDir::home().dirName(), 
                &ok
            );
            if(!ok) { return; }

            try {
                corePtr->addUserToGroup(group.first, text.toStdString());
            } catch (const std::runtime_error &e) {
                QMessageBox msgBox;
                msgBox.setText(e.what());
                msgBox.exec();
            }
        });
    }
}

void sideBar::clearContacts() {
    QLayoutItem *child;
    while ((child = contactsLayout->takeAt(0)) != 0) {
        delete child->widget();
        delete child;
    }
}

void sideBar::clearGroups() {
    QLayoutItem *child;
    while ((child = groupsLayout->takeAt(0)) != 0) {
        delete child->widget();
        delete child;
    }
}

void sideBar::paintEvent(QPaintEvent *)
{
    QStyleOption opt;
    opt.initFrom(this);
    QPainter p(this);
    style()->drawPrimitive(QStyle::PE_Widget, &opt, &p, this);
}

QTView::QTView(int argc, char *argv[], model::Core *core) : QApplication(argc, argv), View(core),
        centralWidget{new QWidget(&mainWindow)}, chatPage{new Page(core, &mainWindow)}, sidebar{new sideBar(core, &mainWindow)}
{
    mainWindow.setWindowTitle("Messagerie Client");
    mainWindow.setFixedSize(800, 600);

    // Create central widget
    mainWindow.setCentralWidget(centralWidget);

    QHBoxLayout *centralLayout = new QHBoxLayout(centralWidget);
    centralLayout->addWidget(sidebar);
    centralLayout->addWidget(chatPage);

    mainWindow.show();
    QStringList creds;
    bool ok{};
    while(!ok) {
        ok = true;
        creds = LoginDialog::getStrings(nullptr, &ok);
        if(creds[0].isEmpty() || creds[1].isEmpty()) {
            ok = false; continue;
        }

        try {
            core->login(creds[0].toStdString(), creds[1].toStdString());
        } catch (const std::runtime_error &e) {
            try {
                core->registerUser(creds[0].toStdString(), creds[1].toStdString());
                QMessageBox msgBox;
                msgBox.setText("User registered");
                msgBox.exec();
            } catch (const std::runtime_error &e) {
                QMessageBox msgBox;
                msgBox.setText("Authentication failed");
                msgBox.exec();
                ok = false;
            }
        }
    }
    sidebar->updateContacts(core->getContacts(), "");
    sidebar->updateGroups(core->getGroups(), "-1");
}

void QTView::run() {
    exec();    
}

void QTView::update(const nvs::Subject *subject, const std::string &element) {
    if(element == "CONTACTS") {
        sidebar->updateContacts(core->getContacts(), core->getCurrentDestination().id);
        sidebar->updateGroups(core->getGroups(), core->getCurrentDestination().id);
    } else if(element == "MESSAGES") {
        chatPage->updateMessages(core->getMessages());
    } else if(element == "CYCLIC_UPDATE") {
        QMetaObject::invokeMethod(this, [&]() {
            sidebar->updateContacts(core->getContacts(), core->getCurrentDestination().id);
            sidebar->updateGroups(core->getGroups(), core->getCurrentDestination().id);
            chatPage->updateMessages(core->getMessages());
        }, Qt::QueuedConnection);
    }
}

LoginDialog::LoginDialog(QWidget *parent) : QDialog(parent) {
    QFormLayout *lytMain = new QFormLayout(this);

    QLabel *nameLabel = new QLabel("Username:", this);
    QLineEdit *nameLine = new QLineEdit(this);
    lytMain->addWidget(nameLabel);
    lytMain->addWidget(nameLine);
    fields << nameLine;

    QLabel *passwordLabel = new QLabel("Password:", this);
    QLineEdit *passwordLine = new QLineEdit(this);
    lytMain->addWidget(passwordLabel);
    lytMain->addWidget(passwordLine);
    fields << passwordLine;

    QDialogButtonBox *buttonBox = new QDialogButtonBox
            ( QDialogButtonBox::Ok,
              Qt::Horizontal, this );
    lytMain->addWidget(buttonBox);

    bool conn = connect(buttonBox, &QDialogButtonBox::accepted,
                   this, &LoginDialog::accept);
    Q_ASSERT(conn);
    conn = connect(buttonBox, &QDialogButtonBox::rejected,
                   this, &LoginDialog::reject);
    Q_ASSERT(conn);

    setLayout(lytMain);
}

QStringList LoginDialog::getStrings(QWidget *parent, bool *ok)
{
    LoginDialog *dialog = new LoginDialog(parent);

    QStringList list;

    const int ret = dialog->exec();
    if (ok)
        *ok = !!ret;

    if (ret) {
        foreach (auto field, dialog->fields) {
            list << field->text();
        }
    }

    dialog->deleteLater();

    return list;
}

}; // namespace view
