import ctypes
import json
import os
import re
import threading
import time
import traceback
from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtWidgets import QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QPushButton, QScrollArea, QSizePolicy, QTabBar, QTabWidget, QToolButton, QVBoxLayout, QWidget

from .composition import _composition_item_label, match_composition_components, read_chitu_hook_model_names, suggest_composition_matches, summarize_unmatched
from .ctb_file import extract_ctb_machine_name
from .logs import logmsg
from .printer_row import PrinterRowWidget
from .protocol import LOADWINDOW_CLOSE_NOTIFY
from .scalex import fetch_all_warehouse_components, fetch_printers, save_ctb_composition
from .sender import sanitize_upload_name, send_in_background
from .winfocus import force_window_to_foreground


class PickerWindow(QMainWindow):
    """One per captured file - the desktop replacement for the old
    PAGE_HTML page. file_path/filename/machine_name are known up front
    (no PENDING/id indirection needed any more - this window IS the state,
    there's no HTTP boundary between it and slm_chitu_send's own backend
    functions any more)."""

    _progress_signal = Signal(str, object, list)   # phase, percent(float|None), targets(list[dict])
    _printers_signal = Signal(list, str)           # printers, error message ("" if ok)
    _retry_signal = Signal(list)                   # targets(list[dict]) - one row's own retry, not the whole-batch state
    _composition_signal = Signal(list, str)        # warehouse components, error message ("" if ok)
    closed = Signal(object)                        # emitted from closeEvent - PickerHost drops this window's tab

    def __init__(self, file_path, filename, machine_name, chitubox_conn=None):
        super().__init__()
        self.file_path = file_path
        self.filename = filename
        self.machine_name = (machine_name or "").strip() or None
        # 2026-09-08 (experimental): the live CHITUBOX TCP connection this
        # capture came from, if any (a _ChituboxConn - thread-safe wrapper,
        # see its own docstring - not a raw socket; None for
        # slicer_file_watcher()'s backstop path, which has no connection at
        # all) - kept only so closeEvent() can try to notify CHITUBOX this
        # window closed. See LOADWINDOW_CLOSE_NOTIFY's comment for why.
        self.chitubox_conn = chitubox_conn
        try:
            self.file_size = os.path.getsize(file_path)
        except OSError:
            self.file_size = None  # memory_fit_label just stays hidden on every row rather than guessing
        # 2026-09-24: ChituHook/goo_hook's per-model sidecar JSON, if one
        # landed next to this capture (see read_chitu_hook_model_names) -
        # empty when the hook is disabled/not installed (its default state
        # as of this writing) or the file was saved before this feature
        # existed. composition_matched/unmatched are filled in once
        # _start_fetch_composition()'s background fetch of ScaleX's
        # warehouse components resolves - see _on_composition_loaded.
        self.model_names = read_chitu_hook_model_names(file_path) or []
        self.composition_matched = []    # list[(component_dict, quantity)]
        self.composition_ambiguous = []  # list[(model_name, candidates, quantity)] - see match_composition_components
        self.composition_unmatched = []  # list[str] - model names with no exact code match
        self.composition_choice_combos = {}  # model_name -> QComboBox, one per ambiguous group (operator's article pick)
        self.rows = {}       # printer_id -> PrinterRowWidget
        self._loaded_once = False
        # 2026-10-16: several sends may be in flight from one window (the operator
        # can pick more printers while earlier ones are still uploading) - each
        # row remembers the settings of the batch that locked it, for its own retry.
        self._row_params = {}                # printer_id -> (display_name, start_print, test_print)
        self._composition_saved_names = set()  # file names whose composition was already saved from this window
        self._last_display_name = None  # set by _on_send_clicked, reused by a single-row retry
        self._last_start_print = False
        self._last_test_print = False

        self.setWindowTitle("Network sending — %s" % filename)
        self.resize(760, 820)

        central = QWidget()
        central.setObjectName("pickerCentral")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(8)

        # Fixed vertical policy on every label above the form: QLabel's
        # default ("Preferred") is technically allowed to grow past its
        # sizeHint whenever nothing else claims the leftover space,
        # which Qt was doing here - splitting the window's extra height
        # evenly between eyebrow/heading/loading_label into visible gaps.
        # Fixed rules that out unconditionally, so form_widget's own
        # stretch=1 below is the *only* thing that can ever claim leftover
        # vertical space, in every state (loading/error/loaded).
        eyebrow = QLabel("SCALEX LAN MANAGER · NETWORK SENDING")
        eyebrow.setObjectName("eyebrowLabel")
        eyebrow.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        root.addWidget(eyebrow)
        heading = QLabel("Куда отправить файл?")
        heading.setObjectName("headingLabel")
        heading.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        root.addWidget(heading)

        self.loading_label = QLabel("Загружаю список принтеров с ScaleX…")
        self.loading_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.loading_label.setWordWrap(True)
        root.addWidget(self.loading_label)

        self.form_widget = QWidget()
        form = QVBoxLayout(self.form_widget)
        form.setContentsMargins(0, 0, 0, 0)
        form.setSpacing(8)
        self.form_widget.setVisible(False)
        self.form_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        root.addWidget(self.form_widget, 1)

        form.addWidget(self._field_label("Имя файла (можно изменить перед отправкой)"))
        self.filename_edit = QLineEdit(filename)
        form.addWidget(self.filename_edit)

        # 2026-09-25 (user request): hidden, not removed - never actually
        # used in practice, but _render_list()/matches_filters() still read
        # self.search_edit.text() (always "" now), so keeping the widget
        # around means no changes needed to that filtering logic or its
        # tests, just nothing visible to type into.
        search_label = self._field_label("Поиск принтера")
        search_label.setVisible(False)
        form.addWidget(search_label)
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("имя, IP, модель…")
        self.search_edit.textChanged.connect(self._render_list)
        self.search_edit.setVisible(False)
        form.addWidget(self.search_edit)

        self.machine_notice = QLabel()
        self.machine_notice.setObjectName("machineNotice")
        self.machine_notice.setVisible(False)
        form.addWidget(self.machine_notice)

        # 2026-09-24: composition (ChituHook model list -> ScaleX warehouse
        # components, see match_composition_components) - review-only panel;
        # actually saved to ScaleX in _on_send_clicked, alongside the send
        # itself, not from a separate button (per user request). Hidden
        # entirely unless a ChituHook sidecar was actually found for this
        # capture - see model_names above.
        self.composition_notice = QLabel()
        self.composition_notice.setObjectName("machineNotice")
        self.composition_notice.setWordWrap(True)
        self.composition_notice.setVisible(False)
        form.addWidget(self.composition_notice)

        # 2026-09-28 (user request): one name shared by several warehouse
        # articles has no automatically-correct choice (see
        # match_composition_components' "ambiguous" return) - one combo box
        # per ambiguous model name lets the operator pick the target
        # article. Built lazily in _on_composition_loaded() once the actual
        # ambiguous groups (if any) are known; stays empty/invisible
        # otherwise.
        self.composition_ambiguous_widget = QWidget()
        self.composition_ambiguous_layout = QVBoxLayout(self.composition_ambiguous_widget)
        self.composition_ambiguous_layout.setContentsMargins(0, 0, 0, 0)
        self.composition_ambiguous_layout.setSpacing(4)
        self.composition_ambiguous_widget.setVisible(False)
        form.addWidget(self.composition_ambiguous_widget)

        # 2026-10-02 (user request): ScaleX's own «Тестовая - без учёта
        # склада» flag (X-Test-Print / testPrint) - the print is excluded
        # from stock accounting, so no composition is saved for it either
        # (see _save_composition_in_background).
        self.test_print_cb = QCheckBox("Тестовая печать — без учёта склада (состав не сохраняется)")
        self.test_print_cb.toggled.connect(
            lambda checked: self.composition_ambiguous_widget.setEnabled(not checked))
        form.addWidget(self.test_print_cb)

        filters_row = QHBoxLayout()
        self.online_only_cb = QCheckBox("Показывать включённые")
        self.online_only_cb.setChecked(True)
        self.online_only_cb.toggled.connect(self._render_list)
        self.hide_busy_cb = QCheckBox("Скрывать занятые")
        self.hide_busy_cb.setChecked(True)
        self.hide_busy_cb.toggled.connect(self._render_list)
        self.match_only_cb = QCheckBox("Подходит под файл")
        self.match_only_cb.setChecked(True)
        self.match_only_cb.toggled.connect(self._render_list)
        self.match_only_cb.setVisible(False)
        filters_row.addWidget(self.online_only_cb)
        filters_row.addWidget(self.hide_busy_cb)
        filters_row.addWidget(self.match_only_cb)
        filters_row.addStretch(1)
        form.addLayout(filters_row)

        toolbar_row = QHBoxLayout()
        select_all_btn = QPushButton("Выбрать все видимые")
        select_all_btn.clicked.connect(self._select_all_visible)
        clear_all_btn = QPushButton("Снять всё")
        clear_all_btn.clicked.connect(self._clear_all)
        toolbar_row.addWidget(select_all_btn)
        toolbar_row.addWidget(clear_all_btn)
        toolbar_row.addStretch(1)
        self.selected_count_label = QLabel("Выбрано: 0")
        self.selected_count_label.setObjectName("selectedCountLabel")
        toolbar_row.addWidget(self.selected_count_label)
        self.toolbar_row = toolbar_row
        form.addLayout(toolbar_row)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_contents = QWidget()
        self.scroll_contents.setObjectName("pickerScrollContents")
        self.list_layout = QVBoxLayout(self.scroll_contents)
        self.list_layout.setSpacing(6)
        self.list_layout.addStretch(1)  # keeps rows top-aligned as they're added before this
        self.scroll_area.setWidget(self.scroll_contents)
        form.addWidget(self.scroll_area, 1)

        actions_row = QHBoxLayout()
        actions_row.addStretch(1)
        self.close_btn = QPushButton("Закрыть")
        self.close_btn.clicked.connect(self.close)
        self.close_btn.setVisible(False)
        # Two explicit buttons instead of a "start print" checkbox modifying
        # one Send button (per user request 2026-08-25) - a dedicated
        # button for "upload and start printing immediately" makes that a
        # deliberate, visible choice rather than something that quietly
        # changes what the main button does depending on a checkbox state
        # you might not notice you left checked from a previous send.
        self.send_and_start_btn = QPushButton("Загрузить и запустить")
        self.send_and_start_btn.setEnabled(False)
        self.send_and_start_btn.clicked.connect(lambda: self._on_send_clicked(start_print=True))
        self.send_btn = QPushButton("Загрузить")
        self.send_btn.setObjectName("sendBtn")
        self.send_btn.setEnabled(False)
        self.send_btn.clicked.connect(lambda: self._on_send_clicked(start_print=False))
        actions_row.addWidget(self.close_btn)
        actions_row.addWidget(self.send_and_start_btn)
        actions_row.addWidget(self.send_btn)
        self.actions_row = actions_row
        form.addLayout(actions_row)

        self.filename_edit.returnPressed.connect(self.send_btn.click)

        self._progress_signal.connect(self._on_progress, Qt.QueuedConnection)
        self._printers_signal.connect(self._on_printers_loaded, Qt.QueuedConnection)
        self._retry_signal.connect(self._on_retry_progress, Qt.QueuedConnection)
        self._composition_signal.connect(self._on_composition_loaded, Qt.QueuedConnection)

        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(5000)
        self._refresh_timer.timeout.connect(self._start_fetch_printers)

        self._start_fetch_printers(initial=True)
        if self.model_names:
            self.composition_notice.setText("Состав СТБ: подбираю совпадения по данным ChituHook…")
            self.composition_notice.setVisible(True)
            self._start_fetch_composition()

    @staticmethod
    def _field_label(text):
        lbl = QLabel(text)
        lbl.setObjectName("fieldLabel")
        return lbl

    # -- printer loading ----------------------------------------------------
    def _start_fetch_printers(self, initial=False):
        def worker():
            try:
                printers = fetch_printers()
                self._printers_signal.emit(printers, "")
            except Exception as e:
                self._printers_signal.emit([], str(e))
        threading.Thread(target=worker, daemon=True).start()

    def _on_printers_loaded(self, printers, error):
        if error and not self._loaded_once:
            self.loading_label.setText(
                "Не удалось получить список принтеров ScaleX (см. лог). Проверьте, что ScaleX запущен и доступен по сети.")
            return
        if error:
            return  # a background refresh failed - keep showing the last known list, try again next tick

        self._loaded_once = True
        self.loading_label.setVisible(False)
        self.form_widget.setVisible(True)

        if self.machine_name:
            self.machine_notice.setText("Нарезано под: %s" % self.machine_name)
            self.machine_notice.setVisible(True)
            self.match_only_cb.setVisible(True)

        for p in printers:
            pid = str(p.get("id"))
            if pid in self.rows:
                self.rows[pid].apply_data(p)
            else:
                # parent=self.scroll_contents matters here, not just as a
                # style choice: a row created with no parent (the default)
                # stays a genuine top-level widget until _render_list()
                # below happens to insertWidget() it into list_layout - and
                # that only happens for rows that pass the CURRENT filter.
                # Most rows fail the default filters (match_only/
                # online_only/hide_busy) on this very first load, so most
                # rows were never inserted at all and stayed parentless -
                # i.e. real, invisible, ever-growing top-level OS windows -
                # for the rest of the picker's life. This was the actual
                # majority contributor to the topLevelWidgets leak (the
                # setParent(None) call removed elsewhere in this file was a
                # second, smaller contributor on top of this one). Giving
                # every row a real parent up front, before filtering ever
                # runs, fixes it regardless of which rows are visible.
                row = PrinterRowWidget(p, parent=self.scroll_contents, file_size=self.file_size)
                row.on_selection_changed = self._update_selected_count
                row.on_retry_requested = self._retry_single
                self.rows[pid] = row

        self._render_list()
        if not self._refresh_timer.isActive():
            self._refresh_timer.start()

    # -- composition (ChituHook -> ScaleX warehouse components) -------------
    def _start_fetch_composition(self):
        def worker():
            try:
                components = fetch_all_warehouse_components()
                self._composition_signal.emit(components, "")
            except Exception as e:
                self._composition_signal.emit([], str(e))
        threading.Thread(target=worker, daemon=True).start()

    def _on_composition_loaded(self, components, error):
        if error:
            logmsg("=== COMPOSITION: failed to fetch ScaleX warehouse components: %s ===", error)
            self.composition_notice.setVisible(False)
            return
        self.composition_matched, self.composition_ambiguous, self.composition_unmatched = \
            match_composition_components(self.model_names, components)
        self._rebuild_composition_ambiguous_rows()
        if not self.composition_matched and not self.composition_ambiguous and not self.composition_unmatched:
            self.composition_notice.setVisible(False)
            return
        parts = []
        unmatched_detail = ""  # full per-model text, shown as a tooltip when the visible text is a summary
        if self.composition_matched:
            # 2026-09-29 (user request): show the actual detected article
            # per component instead of a generic "this came from ChituHook"
            # caption - the article is the useful thing to glance at here
            # (e.g. to confirm it's the right one before sending), the
            # mechanism explanation is not.
            items = ", ".join(
                "%s×%d" % (_composition_item_label(c), qty)
                for c, qty in self.composition_matched)
            parts.append("Состав СТБ: %s" % items)
        elif not self.composition_ambiguous:
            parts.append("Состав СТБ: ни одна модель с плиты не совпала со складским кодом")
        if self.composition_ambiguous:
            parts.append("Несколько артикулов с одним названием (%d) - выберите целевой артикул ниже:" %
                          len(self.composition_ambiguous))
        if self.composition_unmatched:
            hints = suggest_composition_matches(self.composition_unmatched, components)
            counts = {}
            for n in self.composition_unmatched:
                counts[n] = counts.get(n, 0) + 1
            shown = []
            for n, cnt in counts.items():
                item = n if cnt == 1 else "%s×%d" % (n, cnt)
                if n in hints:
                    item += " (на складе есть похожие: %s)" % " / ".join(hints[n])
                shown.append(item)
            detail = "Без совпадения (%d): %s" % (len(self.composition_unmatched), ", ".join(shown))
            if len(counts) > 3:
                # A whole plate of unknown parts (22 file names with three "similar" codes each)
                # was an unreadable wall of text: say it by article, keep the detail in the tooltip.
                groups = ", ".join("%s ×%d" % g for g in summarize_unmatched(self.composition_unmatched))
                parts.append("Без совпадения (%d): %s - подробности во всплывающей подсказке" %
                             (len(self.composition_unmatched), groups))
                unmatched_detail = detail
            else:
                parts.append(detail)
        self.composition_notice.setText("\n".join(parts))
        self.composition_notice.setToolTip(unmatched_detail)
        self.composition_notice.setVisible(True)

    def _rebuild_composition_ambiguous_rows(self):
        """One row per ambiguous match (see match_composition_components):
        a label naming the model + quantity, and a combo box of candidate
        components (same name, different article/code) for the operator to
        pick the target article from. Rebuilt from scratch on every
        composition load (only actually happens once per picker window, but
        cheap and avoids stale rows if that ever changes)."""
        while self.composition_ambiguous_layout.count():
            item = self.composition_ambiguous_layout.takeAt(0)
            w = item.widget()
            if w:
                w.deleteLater()
        self.composition_choice_combos = {}
        for model_name, candidates, quantity in self.composition_ambiguous:
            row = QHBoxLayout()
            label = QLabel("%s ×%d:" % (model_name, quantity))
            row.addWidget(label)
            combo = QComboBox()
            for c in candidates:
                option_label = c.get("code") or c.get("id")
                combo.addItem(str(option_label), c)
            row.addWidget(combo, 1)
            self.composition_choice_combos[model_name] = combo
            row_widget = QWidget()
            row_widget.setLayout(row)
            self.composition_ambiguous_layout.addWidget(row_widget)
        self.composition_ambiguous_widget.setVisible(bool(self.composition_ambiguous))

    def _save_composition_in_background(self, file_name):
        """Fired from _on_send_clicked, alongside the actual file send - see
        this class's own composition_notice comment for why there's no
        separate button. Best-effort: a failure here is logged only, never
        surfaced to the operator or allowed to block/fail the real send,
        since this is supplementary warehouse bookkeeping, not the transfer
        itself. Deliberately does nothing at all when nothing matched -
        save_ctb_composition() REPLACES ScaleX's existing composition for
        this file name, so calling it with an empty list here would silently
        wipe out a real one an operator assigned by hand.

        Ambiguous matches (see match_composition_components) are resolved
        here from whatever article is currently selected in each combo box
        built by _rebuild_composition_ambiguous_rows() - read at send time,
        not at load time, so a last-second change of selection is honored."""
        if self.test_print_cb.isChecked():
            return  # test print: excluded from stock, nothing to record
        # context -> {component id: quantity}. Components of the two ScaleX
        # warehouses ("warehouse"/"orders") have disjoint ids and a mapping
        # saved under the wrong context's header 404s, so each context's
        # parts are saved in their own PUT (in practice a plate is all one
        # context - orders holds only a handful of Box components).
        by_context = {}

        def add(component, qty):
            ctx = component.get("warehouseContext") or "warehouse"
            bucket = by_context.setdefault(ctx, {})
            bucket[component["id"]] = bucket.get(component["id"], 0) + qty

        for c, qty in self.composition_matched:
            add(c, qty)
        for model_name, candidates, quantity in self.composition_ambiguous:
            combo = self.composition_choice_combos.get(model_name)
            add(combo.currentData() if combo else candidates[0], quantity)
        if not by_context:
            return

        def worker():
            for ctx, counts in by_context.items():
                quantities = list(counts.items())
                try:
                    save_ctb_composition(file_name, quantities, context=ctx)
                    logmsg("=== COMPOSITION: saved %d component(s) for %s (%s) ===",
                           len(quantities), file_name, ctx)
                except Exception as e:
                    logmsg("=== COMPOSITION: failed to save for %s (%s): %s ===", file_name, ctx, e)
        threading.Thread(target=worker, daemon=True).start()

    # -- filtering/rendering -------------------------------------------------
    def _render_list(self):
        query = self.search_edit.text().strip().lower()
        online_only = self.online_only_cb.isChecked()
        hide_busy = self.hide_busy_cb.isChecked()
        match_only = self.match_only_cb.isChecked() and self.match_only_cb.isVisible()

        # remove everything but the trailing stretch, then re-add in sorted,
        # filtered order - cheap (repositioning, not recreating) since rows
        # are persistent widgets.
        #
        # IMPORTANT: only takeAt() here, never setParent(None). takeAt()
        # detaches the widget from the LAYOUT but leaves its Qt parent
        # (scroll_contents) untouched, which is what we want since rows not
        # matching the current filter simply stay an un-laid-out child,
        # invisible, still owned by scroll_contents. Calling setParent(None)
        # on top of that clears the widget's parent entirely, which in Qt
        # promotes it to an independent TOP-LEVEL WIDGET (a real, if
        # invisible, OS window) instead of destroying it - since every row
        # that fails the current filter (search text / online-only /
        # hide-busy / match-only) is never re-inserted, it was orphaned
        # forever as a phantom top-level window every single time
        # _render_list() ran (every 5s printer refresh + every filter
        # keystroke). That's what the topLevelWidgets() diagnostic dump
        # caught: dozens of PrinterRowWidget(visible=False, size=640x480)
        # entries (640x480 is Qt's default size for a parentless widget)
        # accumulating without bound - explaining both the "~5 empty
        # windows" flashes and the picker getting progressively slower to
        # open. Fixed 2026-08-21.
        while self.list_layout.count() > 1:
            self.list_layout.takeAt(0)

        ordered = sorted(self.rows.values(),
                          key=lambda r: (r.printer.get("displayName") or r.printer.get("name") or "").lower())
        for row in ordered:
            # A row that is sending (or shows a result/error) stays on screen whatever the
            # filters say - uploading flips its printer to "busy", which would hide it.
            visible = row.has_progress_shown() or row.matches_filters(query, online_only, hide_busy, match_only, self.machine_name)
            row.setVisible(visible)
            if visible:
                self.list_layout.insertWidget(self.list_layout.count() - 1, row)
        self._update_selected_count()

    def _select_all_visible(self):
        for row in self.rows.values():
            if row.isVisible() and row.checkbox.isEnabled():
                row.checkbox.setChecked(True)

    def _clear_all(self):
        for row in self.rows.values():
            if row.checkbox.isEnabled():
                row.checkbox.setChecked(False)

    def _update_selected_count(self):
        # a locked row (already sending / sent) keeps its checkbox checked but disabled - not selectable again
        n = sum(1 for row in self.rows.values() if row.checkbox.isChecked() and row.checkbox.isEnabled())
        self.selected_count_label.setText("Выбрано: %d" % n)
        self.send_btn.setEnabled(n > 0)
        self.send_and_start_btn.setEnabled(n > 0)

    # -- sending --------------------------------------------------------------
    def _on_send_clicked(self, start_print):
        selected_ids = set()
        targets = []
        for pid, row in self.rows.items():
            if not row.checkbox.isChecked() or not row.checkbox.isEnabled():
                continue
            selected_ids.add(pid)
            apply_rec = row.rec_row.isVisible() and row.rec_checkbox.isChecked()
            targets.append({"printerId": pid, "applyRecommendations": apply_rec})
        if not targets:
            return

        display_name = self.filename_edit.text().strip() or self.filename
        src_ext = os.path.splitext(self.filename)[1]
        if src_ext and not display_name.lower().endswith(src_ext.lower()):
            display_name += src_ext
        clean_name = sanitize_upload_name(display_name)
        if clean_name != display_name:
            logmsg("=== PICKER: file name \"%s\" has characters ScaleX cannot store, sending as \"%s\" ===", display_name, clean_name)
            display_name = clean_name
            self.filename_edit.setText(clean_name)  # show what is actually being sent
        test_print = self.test_print_cb.isChecked()
        # The same name is saved once per window: a second batch of the same file to
        # other printers must not re-PUT the (replace-style) composition.
        if not test_print and display_name not in self._composition_saved_names:
            self._composition_saved_names.add(display_name)
            self._save_composition_in_background(display_name)
        for pid in selected_ids:
            self._row_params[pid] = (display_name, start_print, test_print)

        # The form stays usable: only the rows in this batch are locked, so more
        # printers can be picked and sent while these are still uploading.
        for pid in selected_ids:
            row = self.rows[pid]
            # 2026-09-30 (user report: sending to an already-printing
            # printer visually "squished its card into another one"): a row
            # checked before its printer went busy (with "Скрывать занятые"
            # on) gets filtered OUT of list_layout entirely by _render_list
            # - unlaid-out, not just hidden (see that method's own comment
            # on why: avoids a worse phantom-window leak). set_locked_for_send
            # below force-shows it again regardless, so without re-inserting
            # it into the layout first, Qt renders it at a stale/unmanaged
            # position - overlapping whatever row IS actually laid out
            # there. Only ever needed for a selected row that fell out of
            # the list this way; every already-laid-out row is a no-op here.
            if self.list_layout.indexOf(row) == -1:
                self.list_layout.insertWidget(self.list_layout.count() - 1, row)
            row.set_locked_for_send(True)
        self._update_selected_count()

        logmsg("=== PICKER: sending %s as \"%s\" -> %s (startPrint=%s) ===",
               self.filename, display_name, json.dumps(targets), start_print)

        def report_cb(phase, percent, targets_out):
            self._progress_signal.emit(phase, percent, targets_out)

        send_in_background(self.file_path, targets, display_name=display_name,
                            start_print=start_print, report_cb=report_cb, test_print=test_print)

    def _on_progress(self, phase, percent, targets_out):
        if not targets_out:
            return
        all_done = True
        for t in targets_out:
            row = self.rows.get(str(t["printerId"]))
            if row:
                row.set_mini_progress(t["phase"], t["percent"], t.get("errorReason"))
            if t["phase"] not in ("done", "queued_prepared", "error"):
                all_done = False
        if all_done:
            self.close_btn.setVisible(True)
            self._enable_retry_for_errors(targets_out)

    def _enable_retry_for_errors(self, targets_out):
        """Once every selected printer has reached a terminal state, let
        failures (insufficient printer memory, a rejected upload, whatever)
        be retried immediately from this same window instead of forcing a
        close-and-reopen-and-reselect-from-scratch (per user request
        2026-08-25). No-op on a fully successful send - that just keeps
        the existing "everything's locked, go press Закрыть окно" ending
        unchanged."""
        if not any(t["phase"] == "error" for t in targets_out):
            return
        for t in targets_out:
            row = self.rows.get(str(t["printerId"]))
            if row:
                row.unlock_after_send(succeeded=(t["phase"] != "error"))
        self._render_list()
        self._update_selected_count()

    def _retry_single(self, pid):
        """Wired to every row's on_retry_requested - fires the moment that
        one row's own Retry button is clicked, independent of whether the
        rest of the original batch is still in flight (per user request
        2026-08-25: the row shouldn't have to wait for every other printer
        to finish before it becomes actionable). Reuses whatever filename/
        startPrint the original send used; re-reads applyRecommendations
        fresh off the row in case the user toggled it since. Deliberately
        does NOT touch self.sending or the top-level controls the way a
        full send does - this is a small, single-row side operation that
        can run concurrently with (or standalone from) anything else."""
        row = self.rows.get(pid)
        if not row:
            return
        apply_rec = row.rec_row.isVisible() and row.rec_checkbox.isChecked()
        target = {"printerId": pid, "applyRecommendations": apply_rec}
        display_name, start_print, test_print = self._row_params.get(
            pid, (self._last_display_name or self.filename, self._last_start_print, self._last_test_print))

        row.set_locked_for_send(True)
        logmsg("=== PICKER: retrying %s -> %s (startPrint=%s) ===", self.filename, pid, start_print)

        def report_cb(phase, percent, targets_out):
            self._retry_signal.emit(targets_out)

        send_in_background(self.file_path, [target], display_name=display_name,
                            start_print=start_print, report_cb=report_cb,
                            test_print=test_print)

    def _on_retry_progress(self, targets_out):
        for t in targets_out:
            row = self.rows.get(str(t["printerId"]))
            if not row:
                continue
            row.set_mini_progress(t["phase"], t["percent"], t.get("errorReason"))
            if t["phase"] in ("done", "queued_prepared"):
                row.unlock_after_send(succeeded=True)
            elif t["phase"] == "error":
                # Leave the progress row (error text + re-armed Retry
                # button, both just set by set_mini_progress above)
                # visible - only re-enable the checkbox so the row isn't
                # otherwise stuck locked if they'd rather deselect it than
                # retry again.
                row.checkbox.setEnabled(True)
                row.rec_checkbox.setEnabled(True)

    def closeEvent(self, event):
        try:
            _open_windows.remove(self)
        except ValueError:
            pass
        logmsg("=== picker window closed: %s (%d other picker window(s) still open) ===",
               self.filename, len(_open_windows))
        # 2026-09-08 (experimental, see LOADWINDOW_CLOSE_NOTIFY's comment):
        # tell CHITUBOX this window is gone, unprompted.
        #
        # 2026-09-08 (code-review fix, finding #5): this used to call
        # .send() directly, right here, on the Qt GUI thread. The
        # connection's socket is a plain blocking socket with no timeout
        # ever set anywhere in this file - if CHITUBOX has stopped
        # servicing it without a clean close (crashed, frozen on a native
        # modal, machine asleep), that send() could block for as long as
        # the OS takes to notice the peer is gone (potentially minutes),
        # freezing the ENTIRE app - every window, the tray icon, all of
        # it - not just this one closing window. Firing it from a
        # throwaway daemon thread instead keeps the GUI thread free no
        # matter how long the send takes; _ChituboxConn.send() is already
        # thread-safe (see its own docstring), so this is safe to do from
        # here without any extra locking on this end.
        #
        # 2026-09-29 (investigating "Network sending sometimes does
        # nothing" report): CHITUBOX's own "MainProgramHandle" is the same
        # across every message regardless of which capture it's tied to -
        # its own network-send UI state looks like a single global
        # Visible/not-visible flag, not one per plate/window. Several
        # PickerWindows can be open at once here (one per captured file),
        # so blindly sending Visible:false when ANY one of them closes
        # could tell CHITUBOX "my send window is gone" while a sibling
        # window from the SAME connection is still genuinely open on
        # screen - plausible way for CHITUBOX's own state to get out of
        # sync with reality and start silently ignoring the next click.
        # Only notify when this was the last open window sharing this
        # exact connection.
        chandle = self.chitubox_conn
        if chandle is not None:
            still_open = any(w.chitubox_conn is chandle for w in _open_windows)
            filename = self.filename
            if still_open:
                logmsg("=== close notify SKIPPED for %s: another picker window on the same "
                       "CHITUBOX connection is still open ===", filename)
            else:
                def _notify():
                    ok = chandle.send(LOADWINDOW_CLOSE_NOTIFY)
                    logmsg("=== %s LoadWindow(Visible:false) close notify for %s ===",
                           "SENT" if ok else "SKIPPED (connection already gone)", filename)

                threading.Thread(target=_notify, daemon=True).start()
        super().closeEvent(event)
        self.closed.emit(self)


_open_windows = []  # keeps PickerWindow instances alive - Qt doesn't hold a Python reference on its own


_TRAILING_HEX_SUFFIX_RE = re.compile(r"_[0-9a-f]{8}$", re.IGNORECASE)


def _clean_display_filename(filename):
    """Both capture paths tack a random 8-hex-char suffix onto the slice
    name for on-disk uniqueness only - handle_client()'s own SaveFile
    request names PENDING files "<label>_<uuid4 hex[:8]>.ctb" so re-sending
    the same job twice can't collide, and slicer_file_watcher()'s files
    (named by ChituManager itself, not us) carry the same kind of suffix.
    Necessary on disk, meaningless clutter in the picker's editable
    filename field/window title, and - if the user never bothers to rename
    it - in what actually gets sent to ScaleX as the file name. Strip it
    for display/default purposes only; the real file on disk (and
    self.file_path, which is what's actually uploaded) keeps its unique
    name regardless."""
    stem, ext = os.path.splitext(filename)
    cleaned = _TRAILING_HEX_SUFFIX_RE.sub("", stem)
    return (cleaned or stem) + ext


def open_picker_window(dest_path, chitubox_conn=None):
    """Slot for AppController.file_captured - runs on the GUI thread (the
    signal/slot connection below is queued whenever the emitting thread
    differs from this one, e.g. handle_client()'s background thread), so
    it's safe to create Qt widgets here. chitubox_conn (2026-09-08,
    experimental) is the live CHITUBOX connection this capture came from,
    as a _ChituboxConn (thread-safe wrapper, not a raw socket) - None from
    slicer_file_watcher()'s backstop path, which has none - passed through
    only so the window can notify CHITUBOX when it closes, see
    PickerWindow.closeEvent."""
    filename = _clean_display_filename(os.path.basename(dest_path))
    machine_name = extract_ctb_machine_name(dest_path)
    # 2026-09-29: sibling count logged here too (see closeEvent's own
    # comment) - correlating this against a later "Network sending did
    # nothing" report shows whether CHITUBOX's own send-UI state was
    # already juggling more than one open window at the time.
    logmsg("=== OPENING PICKER: %s (machine=%r, %d other picker window(s) already open) ===",
           filename, machine_name, len(_open_windows))
    win = PickerWindow(dest_path, filename, machine_name, chitubox_conn=chitubox_conn)
    _open_windows.append(win)
    _get_host().add_picker(win)


def _host_title(filenames):
    """Title of the host window - never the bare "Network sending". CHITUBOX announces the
    manager window with Title "Network Sending" (see the LoadWindow message) and appears to
    hide a window carrying exactly that title: with the host so titled the picker stayed
    invisible (2026-10-16/19) and the keyboard focus went to the hidden window. The old
    one-window-per-file titles ("Network sending — <file>") were never affected."""
    if len(filenames) == 1:
        return "Network sending — %s" % filenames[0]
    if len(filenames) > 1:
        return "Network sending — %d плит(ы)" % len(filenames)
    return "Network sending — ScaleX"


class PickerHost(QMainWindow):
    """The single top-level window every PickerWindow lives in, one tab per
    captured file (2026-10-15: sending a batch of plates used to open one
    top-level window each - ten entries in Alt-Tab/the taskbar). The host
    shows itself when the first tab arrives and hides when the last one is
    gone; closing the host closes every tab through the normal
    PickerWindow.closeEvent, so the CHITUBOX close-notify logic is unchanged."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(_host_title([]))
        self.resize(780, 860)
        self._last_reshow = 0.0
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(False)  # own close buttons, see add_picker - the stock ones are unthemeable
        self.tabs.setDocumentMode(True)
        self.tabs.setElideMode(Qt.ElideMiddle)
        self.tabs.setUsesScrollButtons(True)
        self.setCentralWidget(self.tabs)
        # 2026-10-16: seen live - the host window sat hidden (Windows' IsWindowVisible
        # False) with three tabs still in it, so the operator never saw the picker
        # even though captures kept arriving. Cause not pinned down (never
        # reproduced in a fresh process); this re-shows it and logs the evidence.
        self._visibility_timer = QTimer(self)
        self._visibility_timer.setInterval(1500)
        self._visibility_timer.timeout.connect(self._ensure_visible)
        self._visibility_timer.start()

    def add_picker(self, win):
        win.closed.connect(self._on_picker_closed)
        idx = self.tabs.addTab(win, win.filename)
        self.tabs.setTabToolTip(idx, win.filename)
        close_btn = QToolButton()
        close_btn.setObjectName("tabClose")
        close_btn.setText("✕")
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setToolTip("Закрыть")
        close_btn.clicked.connect(lambda _=False, b=close_btn: self._close_tab_of_button(b))
        self.tabs.tabBar().setTabButton(idx, QTabBar.RightSide, close_btn)
        self.tabs.setCurrentIndex(idx)
        self._update_title()
        self.show()
        self.raise_()
        force_window_to_foreground(self)

    def _close_tab_of_button(self, button):
        bar = self.tabs.tabBar()
        for i in range(self.tabs.count()):
            if bar.tabButton(i, QTabBar.RightSide) is button:
                self._close_tab(i)
                return

    def _close_tab(self, index):
        win = self.tabs.widget(index)
        if win is not None:
            win.close()  # closeEvent -> closed signal -> _on_picker_closed removes the tab

    def _on_picker_closed(self, win):
        idx = self.tabs.indexOf(win)
        if idx >= 0:
            self.tabs.removeTab(idx)
            win.setParent(None)
        self._update_title()
        if self.tabs.count() == 0:
            self.hide()

    def _natively_visible(self):
        try:
            return bool(ctypes.windll.user32.IsWindowVisible(int(self.winId())))
        except Exception:
            return True  # can't tell - don't second-guess Qt

    def _ensure_visible(self):
        if self.tabs.count() == 0 or self.isMinimized():
            return
        qt_visible, native_visible = self.isVisible(), self._natively_visible()
        if qt_visible and native_visible:
            return
        # Rate-limited and never takes the foreground: an earlier version called
        # force_window_to_foreground every 1.5 s on a window Windows kept reporting as
        # hidden, which stole the keyboard focus from whatever the operator was typing in.
        now = time.monotonic()
        if now - self._last_reshow < 30:
            return
        self._last_reshow = now
        logmsg("=== PickerHost was hidden with %d tab(s) open (qt visible=%s, native visible=%s) - showing it again ===",
               self.tabs.count(), qt_visible, native_visible)
        if not qt_visible:
            self.show()
        try:
            ctypes.windll.user32.ShowWindow(int(self.winId()), 4)  # SW_SHOWNOACTIVATE
        except Exception:
            pass

    def hideEvent(self, event):
        if self.tabs.count() > 0:
            logmsg("=== PickerHost.hideEvent with %d tab(s) open; stack: %s ===",
                   self.tabs.count(), "".join(traceback.format_stack(limit=10)))
        super().hideEvent(event)

    def _update_title(self):
        self.setWindowTitle(_host_title([self.tabs.widget(i).filename for i in range(self.tabs.count())]))

    def closeEvent(self, event):
        # No confirmation: a send already handed to the background uploader keeps
        # going after its tab is closed, so closing the window loses nothing.
        for i in reversed(range(self.tabs.count())):
            win = self.tabs.widget(i)
            if win is not None:
                win.close()
        super().closeEvent(event)


_host = None  # the one PickerHost, created on first use (needs a QApplication)


def _get_host():
    global _host
    if _host is None:
        _host = PickerHost()
    return _host
