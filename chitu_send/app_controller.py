from PySide6.QtCore import QObject, Signal


class AppController(QObject):
    """Lives on the GUI thread; background threads (CHITUBOX protocol
    handler, filesystem watcher) emit into file_captured instead of calling
    open_picker_window directly, so window creation always happens on the
    right thread regardless of which thread captured the file. The second
    argument (2026-09-08, experimental) is the live CHITUBOX connection a
    capture came from, as a _ChituboxConn (thread-safe wrapper - see its
    own docstring), or None (slicer_file_watcher()'s backstop path has no
    connection at all) - see PickerWindow.closeEvent."""
    file_captured = Signal(str, object)
    # 2026-10-02 (user request): emitted the moment we ask CHITUBOX to save,
    # with the slice's name - CHITUBOX then spends anywhere from a fraction
    # of a second to 30+ s writing a 250-300 MB file before it answers
    # (scales with size, see the log), and nothing on screen says the click
    # registered meanwhile. The GUI thread shows a tray notice.
    save_requested = Signal(str)


controller = None  # created in main(), before any background thread starts
