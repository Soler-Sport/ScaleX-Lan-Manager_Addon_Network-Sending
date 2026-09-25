// Makes CHITUBOX Pro's existing (but hidden) "Network Sending" QML button
// visible again for the ELEGOO Jupiter 2 profile.
//
// Found 2026-09-08 via a (since-removed) full QWidget/QQuickItem tree dump:
// the button already exists in the tree (CusButton_QMLTYPE_18,
// text="Network Sending", sibling of the "Save Slice" button) - it's just
// hidden (visible=false), not missing. own_manager.py (the user's own tray
// bridge to ScaleX LAN Manager) already implements CHITUBOX's own
// network-sending wire protocol (shared memory advertising a localhost TCP
// port, per its own source), so simply making this EXISTING button visible
// again is enough for CHITUBOX's own native click handler to work
// end-to-end with it - no need to intercept/redirect the click at all.
//
// THREADING - the reason this file exists in its current, much smaller
// form: an earlier version of this file also had a periodic full-tree
// diagnostic dump (probe_qml_tree(), now removed - its job is done, we
// found what we needed) called directly from goo_hook.c's own background
// thread (InstallHooksThread). That caused a real crash during a real
// Jupiter-2 Save Slice export on 2026-09-08: Qt objects (QWidget,
// QQuickItem, ...) are only safe to touch from the thread that owns them
// (the Qt GUI/main thread) - calling their methods from any other thread
// is undefined behavior, and it crashed the moment a probe tick happened
// to coincide with real GUI activity (CHITUBOX's own Save-file dialog
// opening/closing). schedule_fix_network_send_button() below is the fix:
// it's the only function goo_hook.c's background thread is allowed to
// call directly, and all it does is hand a lambda to
// QMetaObject::invokeMethod(..., Qt::QueuedConnection) - a call that IS
// documented as thread-safe from any thread - which queues that lambda to
// actually run ON the GUI thread's own event loop. fix_network_send_button
// (the function that actually touches QQuickItem objects) only ever runs
// from inside that queued lambda, i.e. always on the GUI thread, never
// cross-thread.
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QMetaObject>
#include <QtCore/QVariant>
#include <QtCore/QCoreApplication>
#include <QtGui/QGuiApplication>
#include <QtGui/QWindow>
#include <QtQuick/QQuickWindow>
#include <QtQuick/QQuickItem>

extern "C" void hooklog(const char *fmt, ...);

static bool fix_one_button(QQuickItem *item, int depth) {
    if (!item || depth > 14) return false;
    QVariant textProp = item->property("text");
    QString text = textProp.canConvert<QString>() ? textProp.toString() : QString();
    QByteArray className = item->metaObject()->className();
    if (text == QStringLiteral("Network Sending") && className.startsWith("CusButton")) {
        hooklog("fix_network_send_button: found target item (%s), was visible=%d, setting visible=true",
                className.constData(), (int)item->isVisible());
        item->setVisible(true);
        item->setProperty("enabled", true);
        return true;
    }
    const auto children = item->childItems();
    for (QQuickItem *child : children) {
        if (fix_one_button(child, depth + 1)) return true;
    }
    return false;
}

// Only ever called on the GUI thread (via the QueuedConnection dispatch
// below) - safe to touch QQuickItem objects directly here.
static void fix_network_send_button(void) {
    const auto topWindows = QGuiApplication::topLevelWindows();
    for (QWindow *win : topWindows) {
        QQuickWindow *qw = qobject_cast<QQuickWindow*>(win);
        if (qw && qw->contentItem()) {
            if (fix_one_button(qw->contentItem(), 0)) {
                hooklog("fix_network_send_button: done (found and fixed)");
                return;
            }
        }
    }
    /* Not found this time - normal/expected if the user hasn't navigated
     * to the Save Slice screen yet (the button only exists in the tree
     * once that panel has been created at least once). No log spam here;
     * schedule_fix_network_send_button() is called repeatedly, so it'll
     * just succeed on a later tick once the panel exists. */
}

// The ONLY function safe to call from goo_hook.c's own background thread
// (InstallHooksThread). Posts fix_network_send_button to run later, on
// the Qt GUI thread, via its event loop - QMetaObject::invokeMethod's
// context-object overload is documented thread-safe to call from any
// thread. QCoreApplication::instance() is used as the context object
// purely to identify "the GUI thread" (it's constructed there); nothing
// about QCoreApplication itself is touched.
extern "C" void schedule_fix_network_send_button(void) {
    QCoreApplication *app = QCoreApplication::instance();
    if (!app) return; // too early - Qt not initialized yet, try again next tick
    QMetaObject::invokeMethod(app, &fix_network_send_button, Qt::QueuedConnection);
}
