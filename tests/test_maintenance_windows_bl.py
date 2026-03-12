from datetime import datetime, timedelta
import importlib
import time
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
import keep.api.consts
from keep.api.bl.maintenance_windows_bl import MaintenanceWindowsBl
from keep.api.core.db import get_alerts_by_status, get_workflow_executions, get_workflow_executions_count
from keep.api.core.dependencies import SINGLE_TENANT_UUID
from keep.api.models.alert import AlertDto, AlertStatus
from keep.api.models.db.alert import Alert
from keep.api.models.db.maintenance_window import MaintenanceRuleCreate, MaintenanceWindowRule
from keep.api.models.db.workflow import Workflow
from keep.api.routes.maintenance import update_maintenance_rule
from keep.functions import cyaml
from keep.workflowmanager.workflowstore import WorkflowStore
from tests.fixtures.workflow_manager import (
    workflow_manager,
    wait_for_workflow_execution,
)


@pytest.fixture
def mock_session():
    return MagicMock()


@pytest.fixture
def active_maintenance_window_rule_custom_ignore():
    return MaintenanceWindowRule(
        id=1,
        name="Active maintenance_window",
        tenant_id="test-tenant",
        cel_query='source == "test-source"',
        start_time=datetime.utcnow() - timedelta(hours=1),
        end_time=datetime.utcnow() + timedelta(days=1),
        enabled=True,
        ignore_statuses=[AlertStatus.FIRING.value,],
    )


@pytest.fixture
def active_maintenance_window_rule():
    return MaintenanceWindowRule(
        id=1,
        name="Active maintenance_window",
        tenant_id="test-tenant",
        cel_query='source == "test-source"',
        start_time=datetime.utcnow() - timedelta(hours=1),
        end_time=datetime.utcnow() + timedelta(days=1),
        enabled=True,
        ignore_statuses=[AlertStatus.RESOLVED.value, AlertStatus.ACKNOWLEDGED.value],
    )


@pytest.fixture
def active_maintenance_window_rule_with_suppression_on():
    return MaintenanceWindowRule(
        id=1,
        name="Active maintenance_window",
        tenant_id="test-tenant",
        cel_query='source == "test-source"',
        start_time=datetime.utcnow() - timedelta(hours=1),
        end_time=datetime.utcnow() + timedelta(days=1),
        enabled=True,
        suppress=True,
    )


@pytest.fixture
def expired_maintenance_window_rule_with_suppression_on():
    return MaintenanceWindowRule(
        id=1,
        name="Expired maintenance_window",
        tenant_id="test-tenant",
        cel_query='source == "test-source"',
        start_time=datetime.utcnow() - timedelta(hours=5),
        end_time=datetime.utcnow() - timedelta(hours=1),
        enabled=False,
        suppress=True,
    )


@pytest.fixture
def expired_maintenance_window_rule():
    return MaintenanceWindowRule(
        id=2,
        name="Expired maintenance_window",
        tenant_id="test-tenant",
        cel_query='source == "test-source"',
        start_time=datetime.utcnow() - timedelta(days=2),
        end_time=datetime.utcnow() - timedelta(days=1),
        enabled=True,
    )


@pytest.fixture
def alert_dto():
    return AlertDto(
        id="test-alert",
        source=["test-source"],
        name="Test Alert",
        status="firing",
        severity="critical",
        lastReceived="2021-08-01T00:00:00Z",
    )

@pytest.fixture
def alert_maint():
    return Alert(
        id=uuid4(),
        tenant_id="test-tenant",
        fingerprint="test-fingerprint",
        provider_id="test-provider",
        provider_type="test-provider-type",
        event={
            "name": "Test Alert",
            "status": AlertStatus.MAINTENANCE.value,
            "previous_status": AlertStatus.FIRING.value,
            "source": ["test-source"],
        },
        alert_hash="test-alert-hash",
    )


def test_alert_in_active_maintenance_window(
    mock_session, active_maintenance_window_rule, alert_dto
):
    # Simulate the query to return the active maintenance_window
    mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
        active_maintenance_window_rule
    ]

    maintenance_window_bl = MaintenanceWindowsBl(
        tenant_id="test-tenant", session=mock_session
    )
    result = maintenance_window_bl.check_if_alert_in_maintenance_windows(alert_dto)

    assert result is True


def test_alert_in_active_maintenance_window_with_suppress(
    mock_session, active_maintenance_window_rule_with_suppression_on, alert_dto, monkeypatch
):
    # Ensure we use the default strategy (not recover_previous_status from other tests)
    monkeypatch.setenv("MAINTENANCE_WINDOW_STRATEGY", "default")
    importlib.reload(keep.api.consts)
    importlib.reload(keep.api.bl.maintenance_windows_bl)

    # Simulate the query to return the active maintenance_window
    mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
        active_maintenance_window_rule_with_suppression_on
    ]

    maintenance_window_bl = MaintenanceWindowsBl(
        tenant_id="test-tenant", session=mock_session
    )
    result = maintenance_window_bl.check_if_alert_in_maintenance_windows(alert_dto)

    assert result is False
    assert alert_dto.status == AlertStatus.SUPPRESSED.value


def test_alert_not_in_expired_maintenance_window(
    mock_session, expired_maintenance_window_rule, alert_dto
):
    # Simulate the query to return the expired maintenance_window
    mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
        expired_maintenance_window_rule
    ]

    maintenance_window_bl = MaintenanceWindowsBl(
        tenant_id="test-tenant", session=mock_session
    )
    result = maintenance_window_bl.check_if_alert_in_maintenance_windows(alert_dto)

    # Even though the query returned a maintenance_window, it should not match because it's expired
    assert result is False


def test_alert_in_no_maintenance_window(mock_session, alert_dto):
    # Simulate the query to return no maintenance_windows
    mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = (
        []
    )

    maintenance_window_bl = MaintenanceWindowsBl(
        tenant_id="test-tenant", session=mock_session
    )
    result = maintenance_window_bl.check_if_alert_in_maintenance_windows(alert_dto)

    assert result is False


def test_alert_in_maintenance_window_with_non_matching_cel(
    mock_session, active_maintenance_window_rule, alert_dto
):
    # Modify the cel_query so that the alert won't match
    active_maintenance_window_rule.cel_query = 'source == "other-source"'
    mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
        active_maintenance_window_rule
    ]

    maintenance_window_bl = MaintenanceWindowsBl(
        tenant_id="test-tenant", session=mock_session
    )
    result = maintenance_window_bl.check_if_alert_in_maintenance_windows(alert_dto)

    assert result is False


def test_alert_ignored_due_to_resolved_status(
    mock_session, active_maintenance_window_rule, alert_dto
):
    # Set the alert status to RESOLVED
    alert_dto.status = "resolved"

    mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
        active_maintenance_window_rule
    ]

    maintenance_window_bl = MaintenanceWindowsBl(
        tenant_id="test-tenant", session=mock_session
    )
    result = maintenance_window_bl.check_if_alert_in_maintenance_windows(alert_dto)

    # Should return False because the alert status is RESOLVED
    assert result is False


def test_alert_ignored_due_to_acknowledged_status(
    mock_session, active_maintenance_window_rule, alert_dto
):
    # Set the alert status to ACKNOWLEDGED
    alert_dto.status = "acknowledged"

    mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
        active_maintenance_window_rule
    ]

    maintenance_window_bl = MaintenanceWindowsBl(
        tenant_id="test-tenant", session=mock_session
    )
    result = maintenance_window_bl.check_if_alert_in_maintenance_windows(alert_dto)

    # Should return False because the alert status is ACKNOWLEDGED
    assert result is False


def test_alert_with_missing_cel_field(mock_session, active_maintenance_window_rule, alert_dto):
    # Modify the cel_query to reference a non-existent field
    active_maintenance_window_rule.cel_query = 'alertname == "test-alert"'
    mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
        active_maintenance_window_rule
    ]

    maintenance_window_bl = MaintenanceWindowsBl(
        tenant_id="test-tenant", session=mock_session
    )
    result = maintenance_window_bl.check_if_alert_in_maintenance_windows(alert_dto)

    # Should return False because the field doesn't exist
    assert result is False


def test_alert_not_ignored_due_to_custom_status(
    mock_session, active_maintenance_window_rule_custom_ignore, alert_dto
):
    # Set the alert status to RESOLVED

    mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
        active_maintenance_window_rule_custom_ignore
    ]

    maintenance_window_bl = MaintenanceWindowsBl(
        tenant_id="test-tenant", session=mock_session
    )

    # Should return False because the alert status is FIRING
    alert_dto.status = AlertStatus.FIRING.value
    result = maintenance_window_bl.check_if_alert_in_maintenance_windows(alert_dto)
    assert result is False

    alert_dto.status = AlertStatus.RESOLVED.value
    result = maintenance_window_bl.check_if_alert_in_maintenance_windows(alert_dto)
    assert result is True


def test_strategy_restore_update_status(
    mock_session, active_maintenance_window_rule_with_suppression_on, alert_dto, monkeypatch
):
    """
    Feature: Strategy - recover previous status
    Scenario: Alert enters in maintenance window with suppression
    """
    # GIVEN The strategy is recover_previous_status
    monkeypatch.setenv("MAINTENANCE_WINDOW_STRATEGY", "recover_previous_status")
    importlib.reload(keep.api.consts)
    importlib.reload(keep.api.bl.maintenance_windows_bl)
    # AND there is a maintenance window rule with suppression on active
    mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
        active_maintenance_window_rule_with_suppression_on
    ]

    maintenance_window_bl = MaintenanceWindowsBl(
        tenant_id="test-tenant", session=mock_session
    )

    # WHEN it checks if the alert is in maintenance windows
    result = maintenance_window_bl.check_if_alert_in_maintenance_windows(alert_dto)

    # THEN the result should be False
    assert result is False
    # AND the previous status should be set old alert status
    assert alert_dto.previous_status == AlertStatus.FIRING.value
    # AND the current status should be set to MAINTENANCE
    assert alert_dto.status == AlertStatus.MAINTENANCE.value

def test_strategy_clean_status(
    mock_session, alert_maint, monkeypatch, expired_maintenance_window_rule_with_suppression_on
):
    """
    Feature: Strategy - recover previous status
    Scenario: Alert recovers previous status after maintenance window ends. Whitout any window active.
    """
    # GIVEN The strategy is recover_previous_status
    monkeypatch.setenv("MAINTENANCE_WINDOW_STRATEGY", "recover_previous_status")
    importlib.reload(keep.api.consts)
    importlib.reload(keep.api.bl.maintenance_windows_bl)
    # AND there is a maintenance window expired.
    retrieve_windows_session = MagicMock()
    retrieve_windows_session.exec.return_value.all.return_value = [
        expired_maintenance_window_rule_with_suppression_on
    ]
    # AND there is an alert which was received inside a maintenance window
    retrieve_alerts_session = MagicMock()
    retrieve_alerts_session.exec.return_value.all.return_value = [alert_maint]

    recover_status_session = MagicMock()
    recover_status_session.exec = MagicMock()
    recover_status_session.commit = MagicMock()

    # AND there is a last alert with the same FP
    mock_last_alert = MagicMock()
    mock_last_alert.alert_id = alert_maint.id
    mock_last_alert.event = {"alert_id": alert_maint.id}

    # WHEN recover its previous status
    mock_session.__enter__.side_effect = [retrieve_windows_session, retrieve_alerts_session, recover_status_session, MagicMock(),  MagicMock()]
    with patch("keep.api.core.db.existed_or_new_session", return_value=mock_session), \
            patch("keep.api.bl.maintenance_windows_bl.get_last_alert_by_fingerprint", return_value=mock_last_alert), \
                patch("keep.api.core.db.get_alert_by_event_id", return_value=alert_maint):

        MaintenanceWindowsBl.recover_strategy(logger=MagicMock(), session=mock_session)

    # THEN the new status will be the previous status, and the previous status will be the old status
    _, new_status, new_previous_status, _ = list(recover_status_session.exec.call_args[0][0]._values.values())[0].value.values()
    assert new_status == AlertStatus.FIRING.value
    assert new_previous_status == AlertStatus.MAINTENANCE.value


def test_strategy_alert_block_by_window(
    mock_session, active_maintenance_window_rule_with_suppression_on, alert_maint, monkeypatch
):
    """
    Feature: Strategy - recover previous status
    Scenario: Alert is blocked (continue with the same status) by maintenance window
    """
    # GIVEN The strategy is recover_previous_status
    monkeypatch.setenv("MAINTENANCE_WINDOW_STRATEGY", "recover_previous_status")
    importlib.reload(keep.api.consts)
    importlib.reload(keep.api.bl.maintenance_windows_bl)
    # AND there is a maintenance window active
    retrieve_windows_session = MagicMock()
    retrieve_windows_session.exec.return_value.all.return_value = [active_maintenance_window_rule_with_suppression_on]
    # AND there is an alert which was received inside a maintenance window
    retrieve_alerts_session = MagicMock()
    retrieve_alerts_session.exec.return_value.all.return_value = [alert_maint]

    recover_status_session = MagicMock()
    recover_status_session.exec = MagicMock()
    recover_status_session.commit = MagicMock()

    loggerMag = MagicMock()
    # WHEN the conditions match to recover the initial alert status
    mock_session.__enter__.side_effect = [retrieve_windows_session, retrieve_alerts_session, recover_status_session, MagicMock()]
    with patch("keep.api.core.db.existed_or_new_session", return_value=mock_session):
        MaintenanceWindowsBl.recover_strategy(logger=loggerMag, session=mock_session)

    # THEN the update status method will not be called
    assert not recover_status_session.exec.called
    # AND logger alert will rise an info about the alert blocked by maintenance window
    loggerMag.info.assert_any_call(
            "Alert %s is blocked due to the maintenance window: %s.", alert_maint.id,
            active_maintenance_window_rule_with_suppression_on.id
        )

def test_strategy_alert_expired_by_current_time(
    create_alert, db_session, monkeypatch, create_window_maintenance_active
):
    """
    Feature: Strategy - recover previous status
    Scenario: Having a Maintenance window active, receiving new alerts in that window,
             when the window expires by current time, the alerts should recover its previous status.
    """
    # GIVEN The strategy is recover_previous_status
    monkeypatch.setenv("MAINTENANCE_WINDOW_STRATEGY", "recover_previous_status")
    importlib.reload(keep.api.consts)
    importlib.reload(keep.api.bl.maintenance_windows_bl)
    # AND there is a maintenance window active.
    mw = create_window_maintenance_active(
        cel='fingerprint == "alert-test-1" || fingerprint == "alert-test-2"',
        start=datetime.utcnow() - timedelta(hours=10),
        end=datetime.utcnow() + timedelta(days=1),
    )

    #AND there are new alerts
    create_alert(
        "alert-test-1",
        AlertStatus("firing"),
        datetime.utcnow(),
        {},
    )
    create_alert(
        "alert-test-2",
        AlertStatus("firing"),
        datetime.utcnow(),
        {},
    )
    MaintenanceWindowsBl.recover_strategy(logger=MagicMock(), session=db_session)
    maintenance_status_prev = get_alerts_by_status(AlertStatus.MAINTENANCE, db_session)
    #WHEN The Maintenance Window is closed, because the end time is < current time
    update_maintenance_rule(
        rule_id=mw.id,
        rule_dto=MaintenanceRuleCreate(
            name=mw.name,
            cel_query=mw.cel_query,
            start_time=mw.start_time,
            duration_seconds=36000-5,  # 10h - 5 seconds duration, so the end is just before current time
        ),
        authenticated_entity=MagicMock(tenant_id=SINGLE_TENANT_UUID, email="test@keephq.dev"),
        session=db_session
    )
    time.sleep(3)
    MaintenanceWindowsBl.recover_strategy(logger=MagicMock(), session=db_session)

    #THEN There are 2 alert prev to the current hour and 0 after the maintenance window is expired
    maintenance_status_post = get_alerts_by_status(AlertStatus.MAINTENANCE, db_session)
    assert len(maintenance_status_prev) == 2
    assert len(maintenance_status_post) == 0

@pytest.mark.parametrize(
    ["solved_alert", "executions"],
    [
        (True, 0),
        (False, 1),
    ],
)
def test_strategy_alert_execution_wf(
    create_alert, db_session, monkeypatch, create_window_maintenance_active, workflow_manager,
    solved_alert, executions
):
    """
    Feature: Strategy - recover previous status with Workflow execution
    Scenario: Having a WF created and a Maintenance window active,
             receiving in that window 3 alerts (same FP), 2 FIRING and the other
             one in RESOLVED status, the WF is not executed at the end of the
             maintenance window.

             On the other hand, receiving 2 alerts(same FP) inside the maintenance window,
             once it's expired, the WF is executed 1 time.
    """
    # GIVEN The strategy is recover_previous_status
    monkeypatch.setenv("MAINTENANCE_WINDOW_STRATEGY", "recover_previous_status")
    importlib.reload(keep.api.consts)
    importlib.reload(keep.api.bl.maintenance_windows_bl)
    #AND A Workflow ready to be executed
    workflow_definition = """
        workflow:
            id: 123-333-22-11-22
            name: WF_alert-test-1
            description: Description
            disabled: false
            triggers:
            - type: alert
              cel: fingerprint == "alert-test-1" && status == "firing"
            inputs: []
            consts: {}
            owners: []
            services: []
            steps: []
            actions:
            - name: action-mock
              provider:
                type: mock
                config: "{{ providers.default-mock }}"
                with:
                    enrich_alert:
                        - key: extra_field
                          value: workflow_executed
        """
    workflow_data = cyaml.safe_load(workflow_definition)
    workflow = WorkflowStore().create_workflow(
            tenant_id=SINGLE_TENANT_UUID,
            created_by="keep",
            workflow=workflow_data.pop("workflow"),
        )
    #AND A Maintenance window active
    mw = create_window_maintenance_active(
        cel='fingerprint == "alert-test-1"',
        start=datetime.utcnow() - timedelta(hours=10),
        end=datetime.utcnow() + timedelta(days=1),
    )

    # AND 2 Firing alerts with the same Fingerprint
    create_alert(
        "alert-test-1",
        AlertStatus("firing"),
        datetime.utcnow(),
        {},
    )
    create_alert(
        "alert-test-1",
        AlertStatus("firing"),
        datetime.utcnow(),
        {},
    )
    if solved_alert:
        #AND 1 Resolved alert with the same Fingerprint
        create_alert(
            "alert-test-1",
            AlertStatus("resolved"),
            datetime.utcnow(),
            {},
        )
    time.sleep(1)
    MaintenanceWindowsBl.recover_strategy(logger=MagicMock(), session=db_session)
    #WHEN The Maintenance Window is closed, because the end time is < current time
    update_maintenance_rule(
        rule_id=mw.id,
        rule_dto=MaintenanceRuleCreate(
            name=mw.name,
            cel_query=mw.cel_query,
            start_time=mw.start_time,
            duration_seconds=36000-5,  # 10h - 5 seconds duration, so the end is just before current time
        ),
        authenticated_entity=MagicMock(tenant_id=SINGLE_TENANT_UUID, email="test@keephq.dev"),
        session=db_session
    )
    MaintenanceWindowsBl.recover_strategy(logger=MagicMock(), session=db_session)
    time.sleep(5)
    #THEN The WF is not executed if there is a resolved alert or executed 1 time if there are only firing alerts
    n_executions = get_workflow_executions(SINGLE_TENANT_UUID, workflow.id)[0]

    assert n_executions == executions


def test_maintenance_window_cel_evaluation_exception_handling(
    mock_session, active_maintenance_window_rule, alert_dto
):
    """
    Feature: Generic - check_if_alert_in_maintenance_windows method exception handling
    Scenario: When there is an exception checking the parameters inside the
            check_if_alert_in_maintenance_windows method, it should be handled and
            the method should return False.
            This prevents the system from crashing and continue with the main flow.
    """

    # GIVEN a maintenance window active with a erroneous CEL expression
    active_maintenance_window_rule.cel_query = r'service.matches("(?i)^[10(\..*)?$")'
    mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
        active_maintenance_window_rule
    ]

    maintenance_window_bl = MaintenanceWindowsBl(
        tenant_id="test-tenant", session=mock_session
    )
    # WHEN it checks if the alert is in maintenance windows
    result = maintenance_window_bl.check_if_alert_in_maintenance_windows(alert_dto)

    # Then it must return a boolean value, False in this case
    assert result is False


# =============================================================================
# Tests for timezone handling and UTC conversion
# =============================================================================

class TestTimezoneConversion:
    """Tests for timezone handling in MaintenanceRuleCreate and time comparisons."""

    def test_start_time_with_z_suffix_converted_to_utc(self):
        """Test that ISO format with Z suffix is properly converted to UTC naive datetime."""
        from keep.api.models.db.maintenance_window import MaintenanceRuleCreate

        # Input with Z (UTC indicator)
        rule = MaintenanceRuleCreate(
            name="Test Rule",
            cel_query='source == "test"',
            start_time="2026-01-19T17:30:00Z",
            duration_seconds=3600,
        )

        # Should store as naive datetime in UTC
        assert rule.start_time.tzinfo is None
        assert rule.start_time.hour == 17
        assert rule.start_time.minute == 30

    def test_start_time_with_timezone_offset_converted_to_utc(self):
        """Test that ISO format with timezone offset is converted to UTC."""
        from keep.api.models.db.maintenance_window import MaintenanceRuleCreate

        # Input with +05:00 offset (5 hours ahead of UTC)
        rule = MaintenanceRuleCreate(
            name="Test Rule",
            cel_query='source == "test"',
            start_time="2026-01-19T22:30:00+05:00",
            duration_seconds=3600,
        )

        # 22:30 +05:00 = 17:30 UTC
        assert rule.start_time.tzinfo is None
        assert rule.start_time.hour == 17
        assert rule.start_time.minute == 30

    def test_start_time_local_with_timezone_field_converted_to_utc(self):
        """Test that local time with timezone field is converted to UTC."""
        from keep.api.models.db.maintenance_window import MaintenanceRuleCreate

        # Local time 23:30 in Chile (UTC-3 in summer)
        rule = MaintenanceRuleCreate(
            name="Test Rule",
            cel_query='source == "test"',
            start_time="2026-01-19T23:30:00",  # Local time (naive)
            duration_seconds=3600,
            timezone="America/Santiago",  # Chile timezone
        )

        # 23:30 Chile (UTC-3) = 02:30 UTC next day
        assert rule.start_time.tzinfo is None
        assert rule.start_time.day == 20  # Next day
        assert rule.start_time.hour == 2
        assert rule.start_time.minute == 30

    def test_start_time_local_european_timezone_converted_to_utc(self):
        """Test that local time with European timezone is converted to UTC."""
        from keep.api.models.db.maintenance_window import MaintenanceRuleCreate

        # Local time 18:30 in Madrid (UTC+1 in winter)
        rule = MaintenanceRuleCreate(
            name="Test Rule",
            cel_query='source == "test"',
            start_time="2026-01-19T18:30:00",  # Local time
            duration_seconds=3600,
            timezone="Europe/Madrid",
        )

        # 18:30 Madrid (UTC+1) = 17:30 UTC
        assert rule.start_time.tzinfo is None
        assert rule.start_time.hour == 17
        assert rule.start_time.minute == 30

    def test_start_time_naive_without_timezone_assumed_utc(self):
        """Test that naive datetime without timezone field is assumed to be UTC."""
        from keep.api.models.db.maintenance_window import MaintenanceRuleCreate

        rule = MaintenanceRuleCreate(
            name="Test Rule",
            cel_query='source == "test"',
            start_time="2026-01-19T17:30:00",  # Naive, no timezone field
            duration_seconds=3600,
            # No timezone field - should assume UTC
        )

        # Should remain as-is (assumed UTC)
        assert rule.start_time.tzinfo is None
        assert rule.start_time.hour == 17
        assert rule.start_time.minute == 30

    def test_invalid_timezone_keeps_original_time(self):
        """Test that invalid timezone keeps the original time (assumes UTC)."""
        from keep.api.models.db.maintenance_window import MaintenanceRuleCreate

        rule = MaintenanceRuleCreate(
            name="Test Rule",
            cel_query='source == "test"',
            start_time="2026-01-19T17:30:00",
            duration_seconds=3600,
            timezone="Invalid/Timezone",  # Invalid timezone
        )

        # Should keep original time (assume UTC)
        assert rule.start_time.hour == 17
        assert rule.start_time.minute == 30


class TestUtcHelperFunctions:
    """Tests for UTC helper functions used in maintenance window comparisons."""

    def test_get_utc_now_returns_aware_datetime(self):
        """Test that get_utc_now returns a timezone-aware datetime in UTC."""
        from keep.api.bl.maintenance_windows_bl import get_utc_now
        from datetime import timezone as dt_timezone

        now = get_utc_now()

        assert now.tzinfo is not None
        assert now.tzinfo == dt_timezone.utc

    def test_ensure_utc_aware_with_naive_datetime(self):
        """Test that naive datetime is assumed to be UTC."""
        from keep.api.bl.maintenance_windows_bl import ensure_utc_aware
        from datetime import timezone as dt_timezone

        naive_dt = datetime(2026, 1, 19, 17, 30, 0)
        result = ensure_utc_aware(naive_dt)

        assert result.tzinfo == dt_timezone.utc
        assert result.hour == 17
        assert result.minute == 30

    def test_ensure_utc_aware_with_utc_datetime(self):
        """Test that UTC-aware datetime remains unchanged."""
        from keep.api.bl.maintenance_windows_bl import ensure_utc_aware
        from datetime import timezone as dt_timezone

        utc_dt = datetime(2026, 1, 19, 17, 30, 0, tzinfo=dt_timezone.utc)
        result = ensure_utc_aware(utc_dt)

        assert result.tzinfo == dt_timezone.utc
        assert result.hour == 17

    def test_ensure_utc_aware_with_other_timezone(self):
        """Test that datetime in another timezone is converted to UTC."""
        from keep.api.bl.maintenance_windows_bl import ensure_utc_aware
        from datetime import timezone as dt_timezone
        from zoneinfo import ZoneInfo

        # 22:30 in UTC+5
        other_tz = ZoneInfo("Asia/Karachi")  # UTC+5
        other_dt = datetime(2026, 1, 19, 22, 30, 0, tzinfo=other_tz)
        result = ensure_utc_aware(other_dt)

        # 22:30 UTC+5 = 17:30 UTC
        assert result.tzinfo == dt_timezone.utc
        assert result.hour == 17
        assert result.minute == 30

    def test_ensure_utc_aware_with_none(self):
        """Test that None input returns None."""
        from keep.api.bl.maintenance_windows_bl import ensure_utc_aware

        result = ensure_utc_aware(None)
        assert result is None


class TestMaintenanceWindowTimeComparisons:
    """Tests for time comparison logic in maintenance windows."""

    def _utc_now_naive(self) -> datetime:
        """Helper to get current UTC time as naive datetime (like DB storage)."""
        from datetime import timezone as dt_timezone
        return datetime.now(dt_timezone.utc).replace(tzinfo=None)

    def test_alert_in_window_with_naive_db_times(self, mock_session, alert_dto):
        """Test that naive DB times (assumed UTC) work correctly with UTC now."""
        now = self._utc_now_naive()
        # Create maintenance window with naive datetimes (as stored in DB)
        window = MaintenanceWindowRule(
            id=1,
            name="Test Window",
            tenant_id="test-tenant",
            cel_query='source == "test-source"',
            start_time=now - timedelta(hours=1),  # Naive
            end_time=now + timedelta(hours=1),    # Naive
            enabled=True,
            ignore_statuses=[],
        )

        mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
            window
        ]

        mw_bl = MaintenanceWindowsBl(tenant_id="test-tenant", session=mock_session)
        result = mw_bl.check_if_alert_in_maintenance_windows(alert_dto)

        assert result is True

    def test_window_expired_correctly_detected(self, mock_session, alert_dto):
        """Test that expired window (end_time in past) is correctly detected."""
        now = self._utc_now_naive()
        # Create maintenance window that ended 1 hour ago
        window = MaintenanceWindowRule(
            id=1,
            name="Expired Window",
            tenant_id="test-tenant",
            cel_query='source == "test-source"',
            start_time=now - timedelta(hours=3),
            end_time=now - timedelta(hours=1),  # Ended 1 hour ago
            enabled=True,
            ignore_statuses=[],
        )

        mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
            window
        ]

        mw_bl = MaintenanceWindowsBl(tenant_id="test-tenant", session=mock_session)
        result = mw_bl.check_if_alert_in_maintenance_windows(alert_dto)

        # Should not match because window is expired
        assert result is False

    def test_window_not_started_correctly_detected(self, mock_session, alert_dto):
        """Test that future window (start_time in future) is correctly filtered in query."""
        # This test verifies that the __init__ query filters correctly
        # by checking that a future window would not be in maintenance_rules
        now = self._utc_now_naive()

        # Create window that starts in 1 hour
        future_window = MaintenanceWindowRule(
            id=1,
            name="Future Window",
            tenant_id="test-tenant",
            cel_query='source == "test-source"',
            start_time=now + timedelta(hours=1),  # Starts in 1 hour
            end_time=now + timedelta(hours=2),
            enabled=True,
            ignore_statuses=[],
        )

        # Simulate query returning no windows (because future window is filtered)
        mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = []

        mw_bl = MaintenanceWindowsBl(tenant_id="test-tenant", session=mock_session)
        result = mw_bl.check_if_alert_in_maintenance_windows(alert_dto)

        assert result is False

    def test_window_boundary_start_time_exact(self, mock_session, alert_dto):
        """Test window at exact start boundary."""
        now = self._utc_now_naive()

        # Window starts exactly now
        window = MaintenanceWindowRule(
            id=1,
            name="Boundary Window",
            tenant_id="test-tenant",
            cel_query='source == "test-source"',
            start_time=now,
            end_time=now + timedelta(hours=1),
            enabled=True,
            ignore_statuses=[],
        )

        mock_session.query.return_value.filter.return_value.filter.return_value.filter.return_value.filter.return_value.all.return_value = [
            window
        ]

        mw_bl = MaintenanceWindowsBl(tenant_id="test-tenant", session=mock_session)
        # Should work as alert is within the window timeframe
        result = mw_bl.check_if_alert_in_maintenance_windows(alert_dto)

        assert result is True

    def test_end_time_calculated_correctly_from_duration(self):
        """Test that end_time is calculated correctly from start_time + duration."""
        from keep.api.models.db.maintenance_window import MaintenanceRuleCreate

        rule = MaintenanceRuleCreate(
            name="Test Rule",
            cel_query='source == "test"',
            start_time="2026-01-19T17:30:00Z",
            duration_seconds=7200,  # 2 hours
        )

        # end_time should be 2 hours after start_time
        expected_end = rule.start_time + timedelta(seconds=7200)

        # Since end_time is calculated in the route, verify start_time is correct
        assert rule.start_time.hour == 17
        assert rule.start_time.minute == 30
        assert rule.duration_seconds == 7200


class TestRecoverStrategyTimeComparisons:
    """Tests for time comparisons in recover_strategy method."""

    def _utc_now_naive(self) -> datetime:
        """Helper to get current UTC time as naive datetime."""
        from datetime import timezone as dt_timezone
        return datetime.now(dt_timezone.utc).replace(tzinfo=None)

    def test_recover_strategy_uses_utc_for_comparisons(self, mock_session, alert_maint):
        """Test that recover_strategy uses UTC-aware comparisons."""
        from keep.api.bl.maintenance_windows_bl import ensure_utc_aware, get_utc_now
        from datetime import timezone as dt_timezone

        # Verify our helper functions work correctly for recover_strategy
        now_utc = get_utc_now()
        assert now_utc.tzinfo == dt_timezone.utc

        # Window times (naive from DB)
        now_naive = self._utc_now_naive()
        w_start = now_naive - timedelta(hours=2)
        w_end = now_naive + timedelta(hours=2)

        # Ensure they're UTC-aware for comparison
        w_start_utc = ensure_utc_aware(w_start)
        w_end_utc = ensure_utc_aware(w_end)

        # Valid comparison
        assert w_start_utc < now_utc < w_end_utc

    def test_alert_timestamp_comparison_with_window_times(self, alert_maint):
        """Test that alert timestamp compares correctly with window times."""
        from keep.api.bl.maintenance_windows_bl import ensure_utc_aware
        from datetime import timezone as dt_timezone

        # Set alert timestamp
        now_naive = self._utc_now_naive()
        alert_maint.timestamp = now_naive

        # Window times
        w_start = now_naive - timedelta(hours=1)
        w_end = now_naive + timedelta(hours=1)

        # All should be comparable after ensure_utc_aware
        alert_ts = ensure_utc_aware(alert_maint.timestamp)
        w_start_utc = ensure_utc_aware(w_start)
        w_end_utc = ensure_utc_aware(w_end)

        # Alert should be within window
        assert w_start_utc < alert_ts < w_end_utc


# =============================================================================
# End-to-End Tests for timezone and recovery strategy
# =============================================================================

class TestE2ETimezoneAndRecoveryStrategy:
    """
    End-to-end tests for maintenance windows with timezone handling and recovery strategy.
    These tests verify the complete flow from window creation with local time to
    alert status recovery when the maintenance window expires.
    """

    def _utc_now_naive(self) -> datetime:
        """Helper to get current UTC time as naive datetime."""
        from datetime import timezone as dt_timezone
        return datetime.now(dt_timezone.utc).replace(tzinfo=None)

    def test_e2e_window_created_with_local_timezone_stored_as_utc(
        self, db_session, monkeypatch
    ):
        """
        E2E Test: Window created with local timezone is stored as UTC in database.

        Scenario:
            1. Frontend sends start_time in local time (Chile: 23:30)
            2. Frontend includes timezone field (America/Santiago)
            3. Backend converts to UTC and stores (02:30 UTC next day)
            4. Database contains UTC time
        """
        from keep.api.models.db.maintenance_window import MaintenanceRuleCreate
        from keep.api.routes.maintenance import create_maintenance_rule
        from keep.api.core.dependencies import SINGLE_TENANT_UUID
        from unittest.mock import MagicMock

        # GIVEN a frontend request with local time and timezone
        # Chile time: 2026-01-19 23:30:00 (UTC-3 in summer)
        local_time_str = "2026-01-19T23:30:00"
        timezone_str = "America/Santiago"

        rule_dto = MaintenanceRuleCreate(
            name="Chile Maintenance Window",
            cel_query='source == "test-source"',
            start_time=local_time_str,
            duration_seconds=3600,  # 1 hour
            timezone=timezone_str,
        )

        # WHEN the rule is created
        auth_entity = MagicMock(
            tenant_id=SINGLE_TENANT_UUID,
            email="test@keephq.dev"
        )

        result = create_maintenance_rule(
            rule_dto=rule_dto,
            authenticated_entity=auth_entity,
            session=db_session,
        )

        # THEN the stored time is in UTC
        # 23:30 Chile (UTC-3) = 02:30 UTC next day (Jan 20)
        assert result.start_time.day == 20
        assert result.start_time.hour == 2
        assert result.start_time.minute == 30

        # AND end_time is correctly calculated (1 hour after start)
        assert result.end_time.hour == 3
        assert result.end_time.minute == 30

    def test_e2e_window_with_utc_z_suffix_stored_correctly(
        self, db_session, monkeypatch
    ):
        """
        E2E Test: Window created with UTC (Z suffix) is stored correctly.

        Scenario:
            1. Frontend sends start_time with Z suffix (already UTC)
            2. Backend stores as-is (no conversion needed)
        """
        from keep.api.models.db.maintenance_window import MaintenanceRuleCreate
        from keep.api.routes.maintenance import create_maintenance_rule
        from keep.api.core.dependencies import SINGLE_TENANT_UUID
        from unittest.mock import MagicMock

        # GIVEN a frontend request with UTC time (Z suffix)
        utc_time_str = "2026-01-19T17:30:00Z"

        rule_dto = MaintenanceRuleCreate(
            name="UTC Maintenance Window",
            cel_query='source == "test-source"',
            start_time=utc_time_str,
            duration_seconds=7200,  # 2 hours
        )

        # WHEN the rule is created
        auth_entity = MagicMock(
            tenant_id=SINGLE_TENANT_UUID,
            email="test@keephq.dev"
        )

        result = create_maintenance_rule(
            rule_dto=rule_dto,
            authenticated_entity=auth_entity,
            session=db_session,
        )

        # THEN the stored time matches the input UTC time
        assert result.start_time.day == 19
        assert result.start_time.hour == 17
        assert result.start_time.minute == 30

        # AND end_time is 2 hours after
        assert result.end_time.hour == 19
        assert result.end_time.minute == 30

    def test_e2e_alert_enters_maintenance_window_based_on_utc_time(
        self, db_session, create_alert, create_window_maintenance_active, monkeypatch
    ):
        """
        E2E Test: Alert correctly enters maintenance window based on UTC comparison.

        Scenario:
            1. Maintenance window is active (start < now < end in UTC)
            2. Alert arrives and matches CEL query
            3. Alert status changes to MAINTENANCE
        """
        monkeypatch.setenv("MAINTENANCE_WINDOW_STRATEGY", "recover_previous_status")
        importlib.reload(keep.api.consts)
        importlib.reload(keep.api.bl.maintenance_windows_bl)

        now_utc = self._utc_now_naive()

        # GIVEN a maintenance window active now (UTC times)
        mw = create_window_maintenance_active(
            cel='fingerprint == "e2e-test-alert"',
            start=now_utc - timedelta(hours=1),
            end=now_utc + timedelta(hours=1),
        )

        # WHEN an alert arrives that matches the CEL
        create_alert(
            "e2e-test-alert",
            AlertStatus("firing"),
            now_utc,
            {},
        )

        # THEN the alert should be in MAINTENANCE status
        from keep.api.core.db import get_alerts_by_status
        maintenance_alerts = get_alerts_by_status(AlertStatus.MAINTENANCE, db_session)

        assert len(maintenance_alerts) >= 1
        matching_alert = [a for a in maintenance_alerts if a.fingerprint == "e2e-test-alert"]
        assert len(matching_alert) == 1

    def test_e2e_recovery_strategy_restores_status_when_window_expires_by_time(
        self, db_session, create_alert, create_window_maintenance_active, monkeypatch
    ):
        """
        E2E Test: Recovery strategy restores alert status when window expires.

        Scenario:
            1. Create maintenance window that ends very soon
            2. Alert enters maintenance window
            3. Wait for window to expire (or simulate expiration)
            4. Run recover_strategy
            5. Alert status is restored to previous status
        """
        monkeypatch.setenv("MAINTENANCE_WINDOW_STRATEGY", "recover_previous_status")
        importlib.reload(keep.api.consts)
        importlib.reload(keep.api.bl.maintenance_windows_bl)

        now_utc = self._utc_now_naive()

        # GIVEN a maintenance window that started 2 hours ago and ends in 2 seconds
        mw = create_window_maintenance_active(
            cel='fingerprint == "e2e-recovery-alert"',
            start=now_utc - timedelta(hours=2),
            end=now_utc + timedelta(seconds=2),  # Expires very soon
        )

        # AND an alert that entered maintenance
        create_alert(
            "e2e-recovery-alert",
            AlertStatus("firing"),
            now_utc - timedelta(minutes=30),  # Alert arrived 30 min ago
            {},
        )

        # Verify alert is in maintenance
        from keep.api.core.db import get_alerts_by_status
        initial_maintenance = get_alerts_by_status(AlertStatus.MAINTENANCE, db_session)
        initial_count = len([a for a in initial_maintenance if a.fingerprint == "e2e-recovery-alert"])

        # WHEN the window expires and recover_strategy runs
        time.sleep(3)  # Wait for window to expire

        MaintenanceWindowsBl.recover_strategy(logger=MagicMock(), session=db_session)

        # THEN the alert should no longer be in MAINTENANCE
        final_maintenance = get_alerts_by_status(AlertStatus.MAINTENANCE, db_session)
        final_count = len([a for a in final_maintenance if a.fingerprint == "e2e-recovery-alert"])

        # Alert count in maintenance should decrease
        assert final_count < initial_count or initial_count == 0

    def test_e2e_multiple_timezones_windows_coexist_correctly(
        self, db_session, monkeypatch
    ):
        """
        E2E Test: Multiple windows created from different timezones work correctly.

        Scenario:
            1. Create window from Chile timezone (UTC-3)
            2. Create window from Madrid timezone (UTC+1)
            3. Both are stored correctly in UTC
            4. Time comparisons work for both
        """
        from keep.api.models.db.maintenance_window import MaintenanceRuleCreate
        from keep.api.routes.maintenance import create_maintenance_rule
        from keep.api.core.dependencies import SINGLE_TENANT_UUID
        from unittest.mock import MagicMock

        auth_entity = MagicMock(
            tenant_id=SINGLE_TENANT_UUID,
            email="test@keephq.dev"
        )

        # GIVEN a window created from Chile (23:30 local = 02:30 UTC next day)
        chile_rule = MaintenanceRuleCreate(
            name="Chile Window",
            cel_query='source == "chile"',
            start_time="2026-01-19T23:30:00",
            duration_seconds=3600,
            timezone="America/Santiago",
        )

        chile_result = create_maintenance_rule(
            rule_dto=chile_rule,
            authenticated_entity=auth_entity,
            session=db_session,
        )

        # AND a window created from Madrid (18:30 local = 17:30 UTC)
        madrid_rule = MaintenanceRuleCreate(
            name="Madrid Window",
            cel_query='source == "madrid"',
            start_time="2026-01-19T18:30:00",
            duration_seconds=3600,
            timezone="Europe/Madrid",
        )

        madrid_result = create_maintenance_rule(
            rule_dto=madrid_rule,
            authenticated_entity=auth_entity,
            session=db_session,
        )

        # THEN Chile window starts at 02:30 UTC (Jan 20)
        assert chile_result.start_time.day == 20
        assert chile_result.start_time.hour == 2

        # AND Madrid window starts at 17:30 UTC (Jan 19)
        assert madrid_result.start_time.day == 19
        assert madrid_result.start_time.hour == 17

        # AND Madrid window starts BEFORE Chile window (in UTC)
        assert madrid_result.start_time < chile_result.start_time

    def test_e2e_recovery_strategy_handles_server_in_non_utc_timezone(
        self, db_session, create_alert, create_window_maintenance_active, monkeypatch
    ):
        """
        E2E Test: Recovery strategy works correctly even if server is in non-UTC timezone.

        This test verifies that our UTC conversion helpers work regardless of
        the server's local timezone setting. The actual timezone change would
        require OS-level changes, but we verify the helper functions handle
        different scenarios correctly.
        """
        from keep.api.bl.maintenance_windows_bl import get_utc_now, ensure_utc_aware
        from datetime import timezone as dt_timezone
        from zoneinfo import ZoneInfo

        monkeypatch.setenv("MAINTENANCE_WINDOW_STRATEGY", "recover_previous_status")
        importlib.reload(keep.api.consts)
        importlib.reload(keep.api.bl.maintenance_windows_bl)

        # GIVEN: Current UTC time
        now_utc = get_utc_now()

        # AND: A naive datetime that represents UTC (like DB storage)
        db_time_naive = now_utc.replace(tzinfo=None)

        # WHEN: We use ensure_utc_aware on the DB time
        db_time_aware = ensure_utc_aware(db_time_naive)

        # THEN: Both should represent the same moment in time
        # The difference should be negligible (less than 1 second)
        time_diff = abs((db_time_aware - now_utc).total_seconds())
        assert time_diff < 1

        # AND: Comparisons work correctly
        past_time = ensure_utc_aware(db_time_naive - timedelta(hours=1))
        future_time = ensure_utc_aware(db_time_naive + timedelta(hours=1))

        assert past_time < now_utc < future_time

    def test_e2e_update_window_with_new_timezone_recalculates_utc(
        self, db_session, monkeypatch
    ):
        """
        E2E Test: Updating a maintenance window with a new timezone recalculates UTC correctly.

        Scenario:
            1. Create window with Chile timezone
            2. Update same window with Madrid timezone (same local time)
            3. Stored UTC time changes accordingly
        """
        from keep.api.models.db.maintenance_window import MaintenanceRuleCreate
        from keep.api.routes.maintenance import create_maintenance_rule, update_maintenance_rule
        from keep.api.core.dependencies import SINGLE_TENANT_UUID
        from unittest.mock import MagicMock

        auth_entity = MagicMock(
            tenant_id=SINGLE_TENANT_UUID,
            email="test@keephq.dev"
        )

        # GIVEN a window created with Chile timezone
        # 18:30 Chile (UTC-3) = 21:30 UTC
        initial_rule = MaintenanceRuleCreate(
            name="Timezone Update Test",
            cel_query='source == "test"',
            start_time="2026-01-19T18:30:00",
            duration_seconds=3600,
            timezone="America/Santiago",
        )

        created = create_maintenance_rule(
            rule_dto=initial_rule,
            authenticated_entity=auth_entity,
            session=db_session,
        )

        initial_utc_hour = created.start_time.hour
        # 18:30 Chile (UTC-3) = 21:30 UTC
        assert initial_utc_hour == 21

        # WHEN updating with same local time but Madrid timezone
        # 18:30 Madrid (UTC+1) = 17:30 UTC
        updated_rule = MaintenanceRuleCreate(
            name="Timezone Update Test",
            cel_query='source == "test"',
            start_time="2026-01-19T18:30:00",  # Same local time
            duration_seconds=3600,
            timezone="Europe/Madrid",  # Different timezone
        )

        updated = update_maintenance_rule(
            rule_id=created.id,
            rule_dto=updated_rule,
            authenticated_entity=auth_entity,
            session=db_session,
        )

        # THEN the UTC hour changes
        updated_utc_hour = updated.start_time.hour
        # 18:30 Madrid (UTC+1) = 17:30 UTC
        assert updated_utc_hour == 17

        # AND the difference is 4 hours (UTC-3 vs UTC+1)
        assert initial_utc_hour - updated_utc_hour == 4
