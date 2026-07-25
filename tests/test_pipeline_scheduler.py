"""Tests for reconforgex.pipeline.scheduler."""

from reconforgex.pipeline.scheduler import PipelineScheduler, Stage, StageResult, StageStatus


class TestPipelineScheduler:
    """Tests for the DAG-based stage scheduler."""

    def test_empty_scheduler(self) -> None:
        scheduler = PipelineScheduler()
        assert len(scheduler) == 0
        assert scheduler.get_execution_order() == []

    def test_single_stage(self) -> None:
        stage = Stage(name="test", description="A test stage", func=lambda: None)
        scheduler = PipelineScheduler([stage])
        waves = scheduler.get_execution_order()
        assert len(waves) == 1
        assert len(waves[0]) == 1
        assert waves[0][0].name == "test"

    def test_dependency_order(self) -> None:
        stage_a = Stage(name="a", description="Stage A", depends_on=[])
        stage_b = Stage(name="b", description="Stage B", depends_on=["a"])
        stage_c = Stage(name="c", description="Stage C", depends_on=["b"])

        scheduler = PipelineScheduler([stage_a, stage_b, stage_c])
        waves = scheduler.get_execution_order()

        assert len(waves) == 3
        assert waves[0][0].name == "a"
        assert waves[1][0].name == "b"
        assert waves[2][0].name == "c"

    def test_concurrent_stages(self) -> None:
        stage_a = Stage(name="a", description="Stage A", depends_on=[])
        stage_b = Stage(name="b", description="Stage B", depends_on=[])
        stage_c = Stage(name="c", description="Stage C", depends_on=["a", "b"])

        scheduler = PipelineScheduler([stage_a, stage_b, stage_c])
        waves = scheduler.get_execution_order()

        assert len(waves) == 2
        # Wave 0: a and b (concurrent)
        assert len(waves[0]) == 2
        names_wave0 = {s.name for s in waves[0]}
        assert names_wave0 == {"a", "b"}
        # Wave 1: c (depends on a and b)
        assert len(waves[1]) == 1
        assert waves[1][0].name == "c"

    def test_register_overwrite(self) -> None:
        scheduler = PipelineScheduler()
        scheduler.register(Stage(name="x", description="Original"))
        scheduler.register(Stage(name="x", description="Overwritten"))
        assert scheduler.get_stage("x").description == "Overwritten"  # type: ignore[union-attr]

    def test_get_stage_missing(self) -> None:
        scheduler = PipelineScheduler()
        assert scheduler.get_stage("nonexistent") is None

    def test_stage_names_property(self) -> None:
        scheduler = PipelineScheduler([
            Stage(name="a", description="A"),
            Stage(name="b", description="B"),
        ])
        assert scheduler.stage_names == ["a", "b"]


class TestStageResult:
    """Tests for the StageResult dataclass."""

    def test_defaults(self) -> None:
        result = StageResult(stage_name="test", status=StageStatus.COMPLETED)
        assert result.data is None
        assert result.error is None
        assert result.duration_seconds == 0.0
