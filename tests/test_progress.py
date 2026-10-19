"""Progress reporting: the main process's step line and the workers' board."""

import multiprocessing

from zircolite.progress import PHASES, Steps, WorkerBoard, show_board, worker_progress


class TestWorkerBoard:
    def test_a_slot_reports_its_file_and_step(self):
        board = WorkerBoard(2)
        slot = board.slot(1, 7)

        slot("reading", 40, 100, events=1_000)
        assert board.rows() == [(7, "reading", 40, 100, 1_000)]

        slot("rules", 3, 9)
        assert board.rows() == [(7, "rules", 3, 9, 1_000)], "the events read stay with the file"

        slot.release()
        assert board.rows() == []

    def test_a_new_file_starts_its_slot_afresh(self):
        board = WorkerBoard(1)
        board.slot(0, 2)("rules", 5, 5, events=10)

        board.slot(0, 3)

        assert board.rows() == [(3, "", 0, 0, 0)]

    def test_more_workers_than_slots_share_rather_than_fail(self):
        board = WorkerBoard(2)
        board.slot(3, 0)("indexing")
        assert board.rows() == [(0, "indexing", 0, 0, 0)]

    def test_unknown_steps_read_as_no_step(self):
        board = WorkerBoard(1)
        board.slot(0, 0)("not a phase", 1, 2)
        assert board.rows() == [(0, "", 1, 2, 0)]
        assert PHASES[0] == ""

    def test_shared_board_lives_in_shared_memory(self):
        board = WorkerBoard.shared(3, multiprocessing.get_context("spawn"))
        board.slot(2, 4)("package", 1, 2)
        assert board.rows() == [(4, "package", 1, 2, 0)]


class TestShowBoard:
    def test_rows_follow_busy_slots_and_finished_files_are_not_counted_twice(self):
        board = WorkerBoard(3)
        progress = worker_progress(name_width=8, disable=True)
        tasks: dict = {}
        board.slot(0, 0)("reading", 50, 100, events=500)
        board.slot(1, 1)("rules", 2, 4, events=300)

        assert show_board(progress, tasks, board, ["a.evtx", "b.evtx"], set()) == 800
        assert len(progress.tasks) == 2
        assert progress.tasks[1].fields["detail"] == "2/4 rules"

        # File 1 finished: the main process has counted its events already.
        assert show_board(progress, tasks, board, ["a.evtx", "b.evtx"], {1}) == 500
        assert [task.description for task in progress.tasks] == ["a.evtx"]

    def test_a_step_of_unknown_size_drops_the_previous_total(self):
        board = WorkerBoard(1)
        progress = worker_progress(disable=True)
        tasks: dict = {}
        slot = board.slot(0, 0)
        slot("reading", 100, 100, events=5)
        show_board(progress, tasks, board, ["a.evtx"], set())

        slot("indexing")
        show_board(progress, tasks, board, ["a.evtx"], set())

        assert progress.tasks[0].total is None
        assert progress.tasks[0].fields["phase"] == "indexing"


class TestSteps:
    def test_a_disabled_line_ignores_reports(self):
        steps = Steps(disable=True)
        steps("reading", 1, 2, events=3, item="x.evtx")
        assert steps._progress is None

    def test_each_step_restarts_and_clear_takes_the_line_down(self):
        steps = Steps(disable=False)
        try:
            steps("reading", 5, 10, events=7, item="[x].evtx")
            task = steps._progress.tasks[0]
            assert task.description == "Reading events [cyan]\\[x].evtx[/]"
            assert (task.completed, task.total) == (5, 10)

            started = task.start_time
            steps("reading", 1, 20, events=9, item="y.evtx")
            task = steps._progress.tasks[0]
            assert task.description.endswith("y.evtx[/]") and task.total == 20
            assert task.start_time == started, "the next file of one step keeps its clock"

            steps("indexing")
            task = steps._progress.tasks[0]
            assert task.description == "Building indexes"
            assert task.total is None and task.completed == 0
        finally:
            steps.clear()
        assert steps._progress is None
