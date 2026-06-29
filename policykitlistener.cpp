// SPDX-FileCopyrightText: 2017 - 2026 UnionTech Software Technology Co., Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later

#include <QDBusConnection>
#include <QDebug>
#include <QFile>
#include <QFileInfo>
#include <QtConcurrent>
#include <QJsonDocument>
#include <QJsonArray>
#include <QDir>
#include <QRegularExpression>
#include <QStringList>

#include <polkit-qt6-1/PolkitQt1/Agent/Listener>

#include "policykitlistener.h"
#include "AuthDialog.h"
#include "authagentadaptor.h"
#include "pluginmanager.h"

#ifdef USE_DEEPIN_POLKIT
static bool isAccountLocked(const PolkitQt1::Identity &identity);
#endif

static bool hasElideMarker(const QString &text)
{
    return text.contains(QStringLiteral("...")) || text.contains(QChar(0x2026));
}

static QStringList commandArgumentsForPid(const QString &pid)
{
    if (pid.isEmpty()) {
        return {};
    }

    QFile cmdlineFile(QStringLiteral("/proc/%1/cmdline").arg(pid));
    if (!cmdlineFile.open(QIODevice::ReadOnly)) {
        return {};
    }

    QStringList args;
    const QList<QByteArray> rawArgs = cmdlineFile.readAll().split('\0');
    for (const QByteArray &rawArg : rawArgs) {
        if (!rawArg.isEmpty()) {
            args << QString::fromLocal8Bit(rawArg);
        }
    }

    return args;
}

static QString processCwdForPid(const QString &pid)
{
    return pid.isEmpty() ? QString() : QFileInfo(QStringLiteral("/proc/%1/cwd").arg(pid)).symLinkTarget();
}

static QString quotedCommandFromMessage(const QString &message)
{
    const qsizetype start = message.indexOf(QLatin1Char('"'));
    const qsizetype end = message.lastIndexOf(QLatin1Char('"'));
    if (start < 0 || end <= start) {
        return QString();
    }

    return message.mid(start + 1, end - start - 1);
}

static QString quoteCommandArgument(QString arg)
{
    if (!arg.contains(QRegularExpression(QStringLiteral("\\s|[\\\"]")))) {
        return arg;
    }

    arg.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    arg.replace(QLatin1Char('"'), QStringLiteral("\\\""));
    return QStringLiteral("\"%1\"").arg(arg);
}

static QString fullCommandFromProcess(const QString &message, const PolkitQt1::Details &details)
{
    QStringList args = commandArgumentsForPid(details.lookup(QStringLiteral("polkit.caller-pid")));
    if (args.isEmpty()) {
        return QString();
    }

    if (QFileInfo(args.constFirst()).fileName() == QStringLiteral("pkexec")) {
        args.removeFirst();
    }
    if (args.isEmpty()) {
        return QString();
    }

    const QString elidedCommand = quotedCommandFromMessage(message);
    const QString messageProgram = elidedCommand.section(QLatin1Char(' '), 0, 0);
    if (messageProgram.isEmpty()) {
        return QString();
    }

    if (QFileInfo(messageProgram).fileName() != QFileInfo(args.constFirst()).fileName()) {
        return QString();
    }

    args[0] = messageProgram;

    QString cwd = processCwdForPid(details.lookup(QStringLiteral("polkit.caller-pid")));
    if (cwd.isEmpty()) {
        cwd = processCwdForPid(details.lookup(QStringLiteral("polkit.subject-pid")));
    }

    for (int i = 1; i < args.size(); ++i) {
        if (!cwd.isEmpty()
                && QFileInfo(args.at(i)).isRelative()
                && (args.at(i).contains(QLatin1Char('/')) || args.at(i).endsWith(QStringLiteral(".deb")))) {
            args[i] = QDir(cwd).absoluteFilePath(args.at(i));
        }
    }

    for (QString &arg : args) {
        arg = quoteCommandArgument(arg);
    }

    return args.join(QLatin1Char(' '));
}

static QStringList processContextForPid(const QString &pid)
{
    QStringList lines;
    QStringList args = commandArgumentsForPid(pid);
    if (!args.isEmpty()) {
        for (QString &arg : args) {
            arg = quoteCommandArgument(arg);
        }
        lines << args.join(QLatin1Char(' '));
    }

    const QString cwd = processCwdForPid(pid);
    if (!cwd.isEmpty()) {
        lines << cwd;
    }

    return lines;
}

static QString authenticationToolTipText(const QString &message, const PolkitQt1::Details &details)
{
    if (!hasElideMarker(message)) {
        return QString();
    }

    const QString fullCommand = fullCommandFromProcess(message, details);
    const qsizetype start = message.indexOf(QLatin1Char('"'));
    const qsizetype end = message.lastIndexOf(QLatin1Char('"'));
    if (!fullCommand.isEmpty() && start >= 0 && end > start) {
        QString toolTipText = message;
        toolTipText.replace(start + 1, end - start - 1, fullCommand);
        return toolTipText;
    }

    QStringList lines{ message };
    lines << processContextForPid(details.lookup(QStringLiteral("polkit.caller-pid")));
    lines << processContextForPid(details.lookup(QStringLiteral("polkit.subject-pid")));
    lines.removeDuplicates();
    return lines.join(QLatin1Char('\n'));
}

PolicyKitListener::PolicyKitListener(QObject *parent)
    : Listener(parent)
    , m_selectedUser(nullptr)
    , m_inProgress(false)
    , m_gainedAuthorization(false)
    , m_wasCancelled(false)
    , m_showInfoSuccess(false)
{
    (void) new AuthAgentAdaptor(this);

    QDBusConnection sessionBus = QDBusConnection::sessionBus();
    if (!sessionBus.registerService("org.deepin.dde.Polkit1.AuthAgent")) {
        qWarning() << "Register auth agent service failed!";
    }
    if (!sessionBus.registerObject("/com/deepin/dde/Polkit1/AuthAgent", this,
                                   QDBusConnection::ExportScriptableSlots |
                                   QDBusConnection::ExportScriptableProperties |
                                   QDBusConnection::ExportAdaptors)) {
        qWarning() << "Register auth agent path failed!";
    }

    qDebug() << "Listener online";

    m_pluginManager = new PluginManager(this);
}

PolicyKitListener::~PolicyKitListener()
{
}

void PolicyKitListener::setWIdForAction(const QString &action, qulonglong wID)
{
    Q_UNUSED(action);
    Q_UNUSED(wID);
    qDebug() << "On to the handshake";
}

void PolicyKitListener::initiateAuthentication(const QString &actionId,
                                               const QString &message,
                                               const QString &iconName,
                                               const PolkitQt1::Details &details,
                                               const QString &cookie,
                                               const PolkitQt1::Identity::List &identities,
                                               PolkitQt1::Agent::AsyncResult *result)
{
    qDebug() << "Initiating authentication";

    if (m_inProgress) {
        result->setError("Another client is already authenticating, please try again later.");
        result->setCompleted();
        qDebug() << "Another client is already authenticating, please try again later.";
        return;
    }

    m_identities = identities;
    m_cookie = cookie;
    m_result = result;
    m_details = details;

    qDebug() << "details: " << m_details.keys();

    m_session.clear();
    m_wasCancelled = false;
    m_inProgress = true;

    m_pluginManager.data()->setActionID(actionId);

    m_dialog = new AuthDialog(message, iconName, authenticationToolTipText(message, details));
    m_dialog->setAttribute(Qt::WA_DeleteOnClose);
    initDialog(actionId);
}

void PolicyKitListener::initDialog(const QString &actionId)
{
    connect(m_dialog.data(), &AuthDialog::accepted, this, &PolicyKitListener::dialogAccepted);
    connect(m_dialog.data(), &AuthDialog::rejected, this, &PolicyKitListener::dialogCanceled);
    connect(m_dialog.data(), &AuthDialog::finished, this, &PolicyKitListener::dialogFinished);
    connect(m_dialog.data(), &AuthDialog::adminUserSelected, this, &PolicyKitListener::createSessionForId);

    // TODO(hualet): show extended action information.
    QList<QButtonGroup *> optionsList = m_pluginManager.data()->reduceGetOptions(actionId);
    for (QButtonGroup *bg : optionsList) {
        m_dialog.data()->addOptions(bg);
    }

    m_dialog.data()->createUserCB(m_identities);

    qDebug() << "WinId of the dialog is " << m_dialog.data()->winId() << m_dialog.data()->effectiveWinId();
    m_dialog.data()->show();
    qDebug() << "WinId of the shown dialog is " << m_dialog.data()->winId() << m_dialog.data()->effectiveWinId();
    m_dialog.data()->activateWindow();
}

void PolicyKitListener::finishObtainPrivilege()
{
    qDebug() << "Finishing obtaining privileges";

    // 插件进行的操作不应该能够长时间阻塞 UI 线程
    // 将插件操作放在新线程中完成的原因是
    // https://gerxxx.xxx.com/c/dpa-ext-gnomekeyring/+/45034/2/gnomekeyringextention.cpp#138
    // 调用了一个可能会阻塞的方法，导致了 bug 82328
    if (m_gainedAuthorization) {
        (void)QtConcurrent::run([=]() {
            QString user = m_selectedUser.toString().remove("unix-user:");
            QString password = m_dialog.data()->password();
            m_pluginManager->reduce(user, password);
        });
    }
#ifdef USE_DEEPIN_POLKIT
    else if (!m_wasCancelled) {
        // 认证失败
        bool isLock = isAccountLocked(m_selectedUser);
        m_dialog->authenticationFailure(isLock);
        if (!isLock) {
            createSessionForId(m_selectedUser); // 重试
        }
        return;
    }
#endif
    // fill complete according to authentication result
    // to get cancel state, polkit-qt need be updated
    fillResult();
    if (!m_session.isNull()) {
        m_session->deleteLater();
    }
    m_dialog->close();

    m_inProgress = false;

    qDebug() << "Finish obtain authorization:" << m_gainedAuthorization;
}

bool PolicyKitListener::initiateAuthenticationFinish()
{
    qDebug() << "Finishing authentication";
    return true;
}

void PolicyKitListener::cancelAuthentication()
{
    qDebug() << "Cancelling authentication";
    m_wasCancelled = true;
}

void PolicyKitListener::request(const QString &request, bool echo)
{
    Q_UNUSED(echo);

    qDebug() << "session request: " << request;

    if (m_dialog && !request.isEmpty()) {
        m_dialog.data()->setAuthInfo(request);
        m_dialog.data()->setInAuth(AuthDialog::WaitingInput);
    }
}

void PolicyKitListener::completed(bool gainedAuthorization)
{
    qDebug() << "session completed: " << gainedAuthorization;

    m_gainedAuthorization = gainedAuthorization;
    if (m_showInfoSuccess)
        m_gainedAuthorization = true;
    m_showInfoSuccess = false;

#ifdef USE_DEEPIN_POLKIT
    if (m_exAuth) {
        m_session.data()->authCtrl(AUTH_CLOSE, -1);
    }
#endif
    finishObtainPrivilege();
    m_dialog.data()->setInAuth(AuthDialog::Completed);
}

void PolicyKitListener::showError(const QString &text)
{
    qDebug() << "show error: " << text;

    if (m_dialog && !text.isEmpty())
        m_dialog.data()->setError(text);
}

void PolicyKitListener::showInfo(const QString &info)
{
    qDebug() << "show info: " << info;

    if (m_dialog && !info.isEmpty())
        m_dialog.data()->setAuthInfo(info);

    if ("Verification successful" == info)
        m_showInfoSuccess = true;
    else
        m_showInfoSuccess = false;
}

void PolicyKitListener::exAuthStatus(int statusCode, int authFlags,
                                     const QString &status) {
    Q_UNUSED(statusCode)
    Q_UNUSED(authFlags)
    qDebug() << "exAuthStatus: " << status;
}

void PolicyKitListener::exAuthInfo(bool isMfa, QList<int> &authTypes) {
    Q_UNUSED(authTypes)
    qDebug() << "exAuthInfo: " << isMfa;
    m_exAuth = true;
    m_isMfa = isMfa;

#ifdef USE_DEEPIN_POLKIT
    if (!isMfa) {
        m_session.data()->authCtrl(AUTH_START, -1);
    }
#endif
}

void PolicyKitListener::dialogAccepted()
{
    if (!m_inProgress || m_session.isNull() || m_dialog.isNull())
        return;

    m_dialog.data()->setInAuth(AuthDialog::Authenticating);
    m_session->setResponse(m_dialog->password());
}

void PolicyKitListener::dialogCanceled()
{
    if (!m_inProgress)
        return;

    qDebug() << "PolicyKitListener::dialogCanceled()";
    m_inProgress = false;
    m_wasCancelled = true;

    // 设置认证结果为取消状态
    fillResult();

    // 清理 session
    if (!m_session.isNull()) {
        m_session->deleteLater();
        m_session = nullptr;
    }

    // 确保对话框关闭
    if (m_dialog) {
        m_dialog->close();
    }
}

void PolicyKitListener::dialogFinished(int result)
{
    Q_UNUSED(result);
    // 确保对话框关闭时清理状态
    // 修复：当用户通过标题栏关闭按钮(X)关闭对话框时，
    // DDialog::closeEvent 使用残留的 clickedButtonIndex 调用 done()，
    // 可能导致触发 accepted() 而非 rejected()，使 m_inProgress 卡死为 true
    if (m_inProgress) {
        dialogCanceled();
    }
}

void PolicyKitListener::createSessionForId(const PolkitQt1::Identity &identity)
{
    m_inProgress = true;
    m_selectedUser = identity;
    // If some user is selected we must destroy existing session
    if (!m_session.isNull()) {
        m_session.data()->deleteLater();
    }
    // We will create new session only when some user is selected
    if (m_selectedUser.isValid()) {
#ifdef USE_DEEPIN_POLKIT
        m_session = new Session(m_selectedUser, m_cookie, m_result, parent(), &m_details);
#else
        m_session = new Session(m_selectedUser, m_cookie, m_result, parent());
#endif

        connect(m_session.data(), &Session::request, this,
                &PolicyKitListener::request);
        connect(m_session.data(), &Session::completed, this,
                &PolicyKitListener::completed);
        connect(m_session.data(), &Session::showError, this,
                &PolicyKitListener::showError);
        connect(m_session.data(), &Session::showInfo, this,
                &PolicyKitListener::showInfo);
#ifdef USE_DEEPIN_POLKIT
        connect(m_session.data(), &Session::exAuthStatus, this,
                &PolicyKitListener::exAuthStatus);
        connect(m_session.data(), &Session::exAuthInfo, this,
                &PolicyKitListener::exAuthInfo);
#endif
        m_session->initiate();
    }
}

void PolicyKitListener::fillResult()
{
    // 始终使用 m_result，因为 session 可能已经 completed
    if (m_wasCancelled) {
#ifdef USE_DEEPIN_POLKIT
        m_result->setCancel("action cancel");
#else
        m_result->setError("action cancel");
#endif
    } else if (!m_gainedAuthorization) {
        m_result->setError("password error");
    }
    m_result->setCompleted();
}

#ifdef USE_DEEPIN_POLKIT
static bool isAccountLocked(const PolkitQt1::Identity &identity)
{
    QString userName = identity.toString().replace("unix-user:", "");
    QDBusMessage msg = QDBusMessage::createMethodCall("org.deepin.dde.Authenticate1",
                                                      "/org/deepin/dde/Authenticate1",
                                                      "org.deepin.dde.Authenticate1",
                                                      "GetLimits");
    msg << userName;
    msg = QDBusConnection::systemBus().call(msg, QDBus::Block, 3000);
    QJsonDocument document;
    if (QDBusMessage::ReplyMessage == msg.type()) {
        document = QJsonDocument::fromJson(msg.arguments().at(0).toString().toUtf8());
    }
    QJsonArray array = document.array();

    bool result = false;
    for (auto item = array.constBegin(); item != array.constEnd(); item++) {
        // 后续可以支持多种认证方式：fingerprint, face, usbkey 等
        if (item->toObject()["type"].toString() == "password") {
            result = item->toObject()["locked"].toBool();
            break;
        }
    }
    return result;
}
#endif
