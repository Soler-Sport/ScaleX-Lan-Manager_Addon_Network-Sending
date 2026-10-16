from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QCheckBox, QFrame, QHBoxLayout, QLabel, QProgressBar, QPushButton, QVBoxLayout, QWidget

from .printers import printer_is_busy, printer_is_online, printer_is_uploading, printer_matches_machine, printer_memory_fit, printer_rec_summary
from .theme import COLOR_RED


TARGET_PHASE_LABELS = {
    "queued": "В очереди",
    "uploading": "Загрузка",
    "sending": "Передача",
    "done": "Готово",
    "error": "Ошибка",
}


ERROR_REASON_LABELS = {
    "low_memory": "Недостаточно памяти на принтере",
    "conflict": "Принтер сейчас занят другой задачей",
}


RETRY_COOLDOWN_MS = 800  # see set_mini_progress() below


class PrinterRowWidget(QFrame):
    """One printer card - persists for the printer's whole lifetime in this
    window (created once when first seen, updated in place on every 5s
    refresh) so filtering/searching never has to save-and-restore checkbox
    state the way the old JS page did (it had to destroy+recreate DOM nodes
    on every re-render; a native widget just gets hidden/shown/repositioned
    instead, so nothing needs to remember what was checked)."""

    def __init__(self, printer, parent=None, file_size=None):
        super().__init__(parent)
        self.setObjectName("printerRow")
        self.setCursor(Qt.PointingHandCursor)
        self.printer_id = str(printer.get("id"))
        self.printer = printer
        self.file_size = file_size  # the picker's own file, in bytes - see memory_fit_label below
        self._has_rec = False  # set for real by apply_data() below; only matters before that if something toggles early

        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 8, 10, 8)
        outer.setSpacing(4)

        top = QHBoxLayout()
        self.checkbox = QCheckBox()
        self.checkbox.toggled.connect(self._on_checkbox_toggled)
        top.addWidget(self.checkbox)

        names = QVBoxLayout()
        names.setSpacing(0)
        self.name_label = QLabel()
        self.name_label.setObjectName("printerName")
        self.meta_label = QLabel()
        self.meta_label.setObjectName("printerMeta")
        # Shows up front, for every card, whether THIS file should fit on
        # THIS printer's currently-reported free space - refreshed on the
        # same 5s cycle as everything else in apply_data() below. Replaces
        # relying on select-send-fail-retry to find out (per user request
        # 2026-08-26: that reactive flow was confusing/felt buggy even
        # after the debounce fix). send_in_background's own pre-check
        # right before actually dispatching is left in place as a last-
        # moment safety net - the printer's real free space can still
        # change in the few seconds between a refresh and an actual send.
        self.memory_fit_label = QLabel()
        self.memory_fit_label.setObjectName("memoryFitLabel")
        self.memory_fit_label.setVisible(False)
        names.addWidget(self.name_label)
        names.addWidget(self.meta_label)
        names.addWidget(self.memory_fit_label)
        top.addLayout(names, 1)

        self.state_label = QLabel()
        self.state_label.setObjectName("stateLabel")
        top.addWidget(self.state_label, 0, Qt.AlignTop)
        outer.addLayout(top)

        # Purely informational labels must not swallow the click - Qt gives
        # the deepest widget under the cursor first dibs at a mouse event
        # and, unlike some event types, an ignored mouse press does NOT
        # automatically bubble up to the parent - so without this, clicking
        # directly on the printer name/meta/state text would do nothing
        # instead of reaching mousePressEvent() below and toggling
        # selection like clicking the empty background already does.
        for lbl in (self.name_label, self.meta_label, self.state_label, self.memory_fit_label):
            lbl.setAttribute(Qt.WA_TransparentForMouseEvents, True)

        self.rec_row = QWidget()
        rec_layout = QHBoxLayout(self.rec_row)
        rec_layout.setContentsMargins(24, 0, 0, 0)
        rec_layout.setSpacing(6)
        self.rec_checkbox = QCheckBox("применить рекомендации:")
        self.rec_summary_label = QLabel()
        self.rec_summary_label.setObjectName("recSummary")
        rec_layout.addWidget(self.rec_checkbox)
        rec_layout.addWidget(self.rec_summary_label, 1)
        outer.addWidget(self.rec_row)

        self.mini_progress = QProgressBar()
        self.mini_progress.setRange(0, 100)
        self.mini_progress_label = QLabel()
        self.mini_progress_label.setObjectName("miniProgressLabel")
        self.retry_btn = QPushButton("Повторить")
        self.retry_btn.setObjectName("retryBtn")
        self.retry_btn.setVisible(False)
        self.retry_btn.clicked.connect(self._on_retry_clicked)
        mini_label_row = QHBoxLayout()
        mini_label_row.setContentsMargins(0, 0, 0, 0)
        mini_label_row.setSpacing(8)
        mini_label_row.addWidget(self.mini_progress_label, 1)
        mini_label_row.addWidget(self.retry_btn)
        mini_wrap = QVBoxLayout()
        mini_wrap.setContentsMargins(24, 2, 0, 0)
        mini_wrap.setSpacing(2)
        mini_wrap.addWidget(self.mini_progress)
        mini_wrap.addLayout(mini_label_row)
        self.mini_progress_widget = QWidget()
        self.mini_progress_widget.setLayout(mini_wrap)
        self.mini_progress_widget.setVisible(False)
        outer.addWidget(self.mini_progress_widget)

        self.on_selection_changed = None  # set by PickerWindow
        self.on_retry_requested = None  # set by PickerWindow
        self.apply_data(printer)

    def mousePressEvent(self, event):
        """Click-to-select: anywhere on the card toggles the same checkbox
        as clicking the checkbox itself (per user request 2026-08-25) - the
        checkbox and rec_checkbox keep their own normal click handling
        since Qt routes a mouse event to the deepest widget under the
        cursor first, and only an unclaimed click (background, or one of
        the labels marked WA_TransparentForMouseEvents above) reaches
        here."""
        if event.button() == Qt.LeftButton and self.checkbox.isEnabled():
            self.checkbox.toggle()
            event.accept()
            return
        super().mousePressEvent(event)

    def _on_retry_clicked(self):
        # Belt-and-braces on top of the cooldown in set_mini_progress()
        # below: set_locked_for_send() (called synchronously inside
        # _retry_single, before any network/thread activity) already hides
        # this button, but disabling it here too closes the gap between
        # this click and that happening.
        self.retry_btn.setEnabled(False)
        if self.on_retry_requested:
            self.on_retry_requested(self.printer_id)

    def _on_checkbox_toggled(self, checked):
        self.setProperty("selected", "true" if checked else "false")
        self.style().unpolish(self)
        self.style().polish(self)

        # Recommendations only matter once you've actually chosen to send
        # here, so keep them out of sight otherwise (per user request
        # 2026-08-25) - and once a printer IS selected, apply its
        # recommended exposure by default rather than making that an extra
        # click every time; the checkbox stays a real override if someone
        # wants to turn it back off for this send.
        self.rec_row.setVisible(checked and self._has_rec)
        if checked and self._has_rec:
            self.rec_checkbox.setChecked(True)

        if self.on_selection_changed:
            self.on_selection_changed()

    def apply_data(self, printer):
        """Refresh from a fresh /api/printers snapshot (live 5s refresh) -
        never touches self.checkbox/self.rec_checkbox so the user's current
        selection survives a background refresh."""
        self.printer = printer
        name = printer.get("displayName") or printer.get("name") or printer.get("liveName") or printer.get("id")
        model = printer.get("model") or printer.get("machineModel") or ""
        ip = printer.get("currentIp") or printer.get("ipAddress") or ""
        self.name_label.setText(str(name))
        self.meta_label.setText("%s — %s" % (model, ip) if model or ip else "")

        fit = printer_memory_fit(printer, self.file_size)
        self.memory_fit_label.setVisible(fit is not None)
        if fit is not None:
            fits, fit_text = fit
            self.memory_fit_label.setText(fit_text)
            self.memory_fit_label.setProperty("fit", "yes" if fits else "no")
            self.memory_fit_label.style().unpolish(self.memory_fit_label)
            self.memory_fit_label.style().polish(self.memory_fit_label)

        prepared = printer.get("operatorPrepared") is True
        if not printer.get("status") or printer.get("status", {}).get("online") is False:
            state, text = "offline", "Оффлайн"
        elif printer_is_uploading(printer):
            state, text = "busy", "Загружается"
        elif printer_is_busy(printer):
            state, text = "busy", "Печатает"
        elif prepared:
            # Merged with the old separate "Принтер подготовлен" badge/row
            # (per user request 2026-08-25) - "prepared" only has anything
            # useful to add once the printer is otherwise available; folded
            # into the same label instead of its own line.
            state, text = "ready", "Доступен и подготовлен"
        else:
            state, text = "ready", "Доступен"
        self.state_label.setText(text)
        self.state_label.setProperty("state", state)
        self.state_label.style().unpolish(self.state_label)
        self.state_label.style().polish(self.state_label)

        summary = printer_rec_summary(printer)
        self._has_rec = bool(summary)
        if self._has_rec:
            self.rec_summary_label.setText(summary)
        self.rec_row.setVisible(self._has_rec and self.checkbox.isChecked())

    def matches_filters(self, query, online_only, hide_busy, match_only, detected_machine):
        if online_only and not printer_is_online(self.printer):
            return False
        if hide_busy and printer_is_busy(self.printer):
            return False
        if match_only and not printer_matches_machine(self.printer, detected_machine):
            return False
        if query:
            hay = " ".join(str(self.printer.get(k) or "") for k in
                            ("displayName", "name", "currentIp", "model", "machineModel")).lower()
            if query not in hay:
                return False
        return True

    def has_progress_shown(self):
        """True while the row shows a send's progress/result/error - such a row must
        stay on screen regardless of the list filters."""
        return self.mini_progress_widget.isVisibleTo(self)

    def set_locked_for_send(self, selected):
        """Called once when a send starts: hides unselected cards, disables
        inputs on the selected ones, and reveals their mini progress bar -
        mirrors the old JS's sendBtn handler, which locked the whole form
        and gave each selected printer its own progress bar in place."""
        self.setVisible(selected)
        if not selected:
            return
        self.checkbox.setEnabled(False)
        self.rec_checkbox.setEnabled(False)
        self.retry_btn.setVisible(False)
        self.mini_progress_widget.setVisible(True)
        self.mini_progress.setRange(0, 0)  # indeterminate
        self.mini_progress_label.setText("В очереди…")

    def unlock_after_send(self, succeeded):
        """Undoes set_locked_for_send() once a row reaches a terminal state
        (per user request 2026-08-25 - a per-printer failure, e.g. not
        enough memory on that specific printer, should be retryable
        without closing/reopening the picker). On success: hide the
        progress row entirely and uncheck, exactly like before this
        existed. On failure: leave the progress row (with its error
        message and the Retry button set_mini_progress just armed) fully
        visible instead of hiding it - that button, not this method, is
        now the primary way to act on the failure, so nothing here should
        make it disappear. Checkbox/rec_checkbox re-enable either way so
        the row isn't stuck locked forever even if the user never clicks
        Retry and instead just wants to deselect it."""
        self.checkbox.setEnabled(True)
        self.rec_checkbox.setEnabled(True)
        if succeeded:
            self.mini_progress_widget.setVisible(False)
            self.checkbox.setChecked(False)

    def _rearm_retry_btn(self):
        # Only matters if the row is still actually showing an error -
        # if it moved on (succeeded on a later retry, got deselected,
        # whatever) in the meantime, retry_btn is already hidden and this
        # is a harmless no-op.
        if self.retry_btn.isVisible():
            self.retry_btn.setEnabled(True)

    def set_mini_progress(self, phase, percent, error_reason=None):
        self.retry_btn.setVisible(phase == "error")
        if phase == "error":
            # Confirmed live 2026-08-25: a memory/conflict pre-check that
            # fails is near-instant (no real network round trip), so
            # without a cooldown the button reappears fast enough that a
            # user tapping it again out of reflex creates a visible rapid
            # show/hide flicker on the whole row ("мигал как ебнутый") -
            # 6+ retries logged inside one second. Keeping it visible (so
            # the error text is readable right away) but disabled for a
            # beat gives a calmer, legible state and stops that loop
            # without making a genuinely-ready retry wait any real time.
            self.retry_btn.setEnabled(False)
            QTimer.singleShot(RETRY_COOLDOWN_MS, self._rearm_retry_btn)
            self.mini_progress.setRange(0, 100)
            self.mini_progress.setValue(100)
            self.mini_progress.setStyleSheet("QProgressBar::chunk { background: %s; }" % COLOR_RED)
            self.mini_progress_label.setText(ERROR_REASON_LABELS.get(error_reason, "Ошибка"))
            return
        self.mini_progress.setStyleSheet("")
        if phase == "done":
            self.mini_progress.setRange(0, 100)
            self.mini_progress.setValue(100)
            self.mini_progress_label.setText("Готово")
            return
        if phase == "queued_prepared":
            # Uploaded, but start was deliberately deferred (printer
            # wasn't operatorPrepared) - registered via ScaleX's own
            # queueIfNotPrepared mechanism instead of starting blind or
            # not starting at all (per user request 2026-08-27). ScaleX
            # itself starts the print once an operator marks the printer
            # prepared - nothing more for slm_chitu_send to do here.
            self.mini_progress.setRange(0, 100)
            self.mini_progress.setValue(100)
            self.mini_progress_label.setText("Загружено — старт назначен, ждём подтверждения подготовки")
            return
        if percent is None:
            self.mini_progress.setRange(0, 0)
        else:
            self.mini_progress.setRange(0, 100)
            self.mini_progress.setValue(max(4, min(100, int(percent))))
        self.mini_progress_label.setText(TARGET_PHASE_LABELS.get(phase, phase))
