import datetime
import json
import logging
from datetime import timezone as dt_timezone

import celpy
from sqlmodel import Session

from keep.api.consts import KEEP_CORRELATION_ENABLED, MAINTENANCE_WINDOW_ALERT_STRATEGY, MAINTENANCE_WINDOW_RECOVERY_HOURS
from opentelemetry import trace
from keep.api.core.db import (
    add_audit,
    existed_or_new_session,
    get_alert_by_event_id,
    get_alerts_by_status,
    get_alerts_by_status_in_timerange,
    get_all_presets_dtos,
    get_last_alert_by_fingerprint,
    get_maintenance_windows_started,
    get_session_sync,
    recover_prev_alert_status,
    set_maintenance_windows_trace,
)
from keep.api.core.dependencies import get_pusher_client
from keep.api.models.action_type import ActionType
from keep.api.models.alert import AlertDto, AlertStatus
from keep.api.models.db.alert import Alert, AlertAudit
from keep.api.models.db.maintenance_window import MaintenanceWindowRule
from keep.api.tasks.notification_cache import get_notification_cache
from keep.api.utils.cel_utils import preprocess_cel_expression
from keep.rulesengine.rulesengine import RulesEngine
from keep.workflowmanager.workflowmanager import WorkflowManager

tracer = trace.get_tracer(__name__)


def get_utc_now() -> datetime.datetime:
    """
    Get the current time in UTC as an aware datetime.
    This works correctly regardless of the server's local timezone.
    """
    return datetime.datetime.now(dt_timezone.utc)


def ensure_utc_aware(dt: datetime.datetime) -> datetime.datetime:
    """
    Ensure a datetime is UTC-aware.
    If the datetime is naive (no tzinfo), assume it represents UTC and add tzinfo.
    If it already has tzinfo, convert it to UTC.

    This is useful for comparing DB times (stored as UTC but may be naive)
    with the current time.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        # Naive datetime - assume it's UTC
        return dt.replace(tzinfo=dt_timezone.utc)
    else:
        # Already has timezone info - convert to UTC
        return dt.astimezone(dt_timezone.utc)


class MaintenanceWindowsBl:

    def __init__(self, tenant_id: str, session: Session | None) -> None:
        self.logger = logging.getLogger(__name__)
        self.tenant_id = tenant_id
        self.session = session if session else get_session_sync()
        now_utc = get_utc_now()
        self.maintenance_rules: list[MaintenanceWindowRule] = (
            self.session.query(MaintenanceWindowRule)
            .filter(MaintenanceWindowRule.tenant_id == tenant_id)
            .filter(MaintenanceWindowRule.enabled == True)
            .filter(MaintenanceWindowRule.end_time >= now_utc.replace(tzinfo=None))
            .filter(MaintenanceWindowRule.start_time <= now_utc.replace(tzinfo=None))
            .all()
        )

    def check_if_alert_in_maintenance_windows(self, alert: AlertDto) -> bool:
        extra = {"tenant_id": self.tenant_id, "fingerprint": alert.fingerprint}

        if not self.maintenance_rules:
            self.logger.debug(
                "No maintenance window rules for this tenant",
                extra={"tenant_id": self.tenant_id},
            )
            return False

        self.logger.info("Checking maintenance window for alert", extra=extra)
        env = celpy.Environment()

        for maintenance_rule in self.maintenance_rules:
            try:
                if alert.status in maintenance_rule.ignore_statuses:
                    self.logger.debug(
                        "Alert status is set to be ignored, ignoring maintenance windows",
                        extra={"tenant_id": self.tenant_id},
                    )
                    continue

                # Compare times in UTC - ensure both are UTC-aware for correct comparison
                rule_end_time_utc = ensure_utc_aware(maintenance_rule.end_time)
                now_utc = get_utc_now()

                if rule_end_time_utc <= now_utc:
                    # this is wtf error, should not happen because of query in init
                    self.logger.error(
                        "Fetched maintenance window which already ended by mistake, should not happen!"
                    )
                    continue

                cel_result = MaintenanceWindowsBl.evaluate_cel(maintenance_rule, alert, env, self.logger, extra)

                if cel_result:
                    self.logger.info(
                        "Alert is in maintenance window",
                        extra={**extra, "maintenance_rule_id": maintenance_rule.id},
                    )

                    try:
                        audit = AlertAudit(
                            tenant_id=self.tenant_id,
                            fingerprint=alert.fingerprint,
                            user_id="Keep",
                            action=ActionType.MAINTENANCE.value,
                            description=(
                                f"Alert in maintenance due to rule `{maintenance_rule.name}`"
                                if not maintenance_rule.suppress
                                else f"Alert suppressed due to maintenance rule `{maintenance_rule.name}`"
                            ),
                        )
                        self.session.add(audit)
                        self.session.commit()
                    except Exception:
                        self.logger.exception(
                            "Failed to write audit for alert maintenance window",
                            extra={
                                "tenant_id": self.tenant_id,
                                "fingerprint": alert.fingerprint,
                            },
                        )

                    if maintenance_rule.suppress:
                        # If user chose to suppress the alert, let it in but override the status.
                        if MAINTENANCE_WINDOW_ALERT_STRATEGY == "recover_previous_status":
                            alert.previous_status = alert.status
                            alert.status = AlertStatus.MAINTENANCE.value
                        else:
                            alert.status = AlertStatus.SUPPRESSED.value
                        return False

                    return True
            except Exception:
                self.logger.exception(
                    "Error while evaluating maintenance window CEL expression",
                    extra={**extra, "maintenance_rule_id": maintenance_rule.id},
                )
        self.logger.info("Alert is not in maintenance window", extra=extra)
        return False

    @staticmethod
    def evaluate_cel(maintenance_window: MaintenanceWindowRule, alert: AlertDto | Alert, environment: celpy.Environment, logger, logger_extra_info: dict) -> bool:

        cel = preprocess_cel_expression(maintenance_window.cel_query)
        ast = environment.compile(cel)
        prgm = environment.program(ast)

        if isinstance(alert, AlertDto):
            payload = alert.dict()
        else:
            payload = alert.event
        # todo: fix this in the future
        payload["source"] = payload["source"][0]

        activation = celpy.json_to_cel(json.loads(json.dumps(payload, default=str)))

        try:
            cel_result = prgm.evaluate(activation)
            return True if cel_result else False
        except celpy.evaluation.CELEvalError as e:
            error_msg = str(e).lower()
            if "no such member" in error_msg or "undeclared reference" in error_msg:
                logger.debug(
                    f"Skipping maintenance window rule due to missing field: {str(e)}",
                    extra={**logger_extra_info, "maintenance_rule_id": maintenance_window.id},
                )
                return False
            # Log unexpected CEL errors but don't fail the entire event processing
            logger.error(
                f"Unexpected CEL evaluation error: {str(e)}",
                extra={**logger_extra_info, "maintenance_rule_id": maintenance_window.id},
            )
            return False

    @staticmethod
    def recover_strategy(
        logger: logging.Logger,
        session: Session | None = None,
    ):
        """

        This strategy will try to recover the previous status of the alerts that were in maintenance windows,
        once the maintenance windows are over, i.e they were deleted.

        For recovering the previous status, the maintenance windows shouldn't exist and the alerts
        should accomplish the following:

            - The alert is in [inhibited_status] status.
            - The alert timestamp is before the maintenance window end time.
            - The alert timestamp is after the maintenance window start time.
            - The CEL expression should match with the both alert and maintenance window.

        Once the status is recovered, Workflows, Correlations/Incidents and Presets will be launched, in the
        same way that a new alert.


        Args:
            logger (logging.Logger): The logger to use.
            session (Session | None): The SQLAlchemy session to use. If None, a new session will be created.
        """
        logger.info("Starting recover strategy for maintenance windows review.")
        env = celpy.Environment()
        with existed_or_new_session(session) as session:
            now_utc = get_utc_now()
            recovery_window = now_utc - datetime.timedelta(hours=MAINTENANCE_WINDOW_RECOVERY_HOURS)

            # Fetch ALL active windows (needed to check if alerts are still blocked)
            # We don't filter windows by time - we filter ALERTS by time
            windows = get_maintenance_windows_started(session)

            # Get unique tenant_ids from active windows to optimize query
            tenant_ids = {window.tenant_id for window in windows}

            if not tenant_ids:
                logger.info("No active maintenance windows found, skipping recovery")
                return

            fingerprints_to_check: set = set()

            # Process alerts by tenant for better performance
            for tenant_id in tenant_ids:
                # Get windows for this tenant (all active, no time filter)
                tenant_windows = [w for w in windows if w.tenant_id == tenant_id]

                if not tenant_windows:
                    continue

                # Calculate search start from maintenance windows, with protection
                min_window_start = min(ensure_utc_aware(w.start_time) for w in tenant_windows)

                # Hybrid approach: use window start time, but cap at recovery_window
                # - If window started 10h ago → search from 10h ago
                # - If window started 3 months ago → limit to recovery_window (e.g., 48h)
                search_start = max(min_window_start, recovery_window)

                # Cursor-based pagination (faster than offset)
                last_timestamp = None
                batch_size = 1000

                while True:
                    alerts_in_maint = get_alerts_by_status_in_timerange(
                        AlertStatus.MAINTENANCE,
                        session,
                        tenant_id=tenant_id,
                        start_time=search_start,
                        end_time=now_utc,
                        limit=batch_size,
                        after_timestamp=last_timestamp
                    )

                    if not alerts_in_maint:
                        break

                    logger.info(f"Processing batch of {len(alerts_in_maint)} alerts for tenant {tenant_id}")

                    # Process alerts
                    for alert in alerts_in_maint:
                        active = False

                        for window in tenant_windows:
                            w_start = ensure_utc_aware(window.start_time)
                            w_end = ensure_utc_aware(window.end_time)
                            alert_timestamp = ensure_utc_aware(alert.timestamp)
                            is_enable = window.enabled

                            # Check active windows - all times are now UTC-aware
                            if (
                                w_start < alert_timestamp
                                and alert_timestamp < w_end
                                and w_end > now_utc
                                and is_enable
                            ):
                                logger.info("Checking alert %s in maintenance window %s", alert.id, window.id)
                                is_in_cel = MaintenanceWindowsBl.evaluate_cel(
                                    window, alert, env, logger, {"tenant_id": alert.tenant_id, "alert_id": alert.id}
                                )
                                # Recover source structure
                                if not isinstance(alert.event.get("source"), list):
                                    alert.event["source"] = [alert.event["source"]]
                                if is_in_cel:
                                    active = True
                                    set_maintenance_windows_trace(alert, window, session)
                                    logger.info("Alert %s is blocked due to the maintenance window: %s.", alert.id, window.id)
                                    break

                        if not active:
                            recover_prev_alert_status(alert, session)
                            fingerprints_to_check.add((alert.tenant_id, alert.fingerprint))
                            add_audit(
                                tenant_id=alert.tenant_id,
                                fingerprint=alert.fingerprint,
                                user_id="system",
                                action=ActionType.MAINTENANCE_EXPIRED,
                                description=(
                                    f"Alert {alert.id} has recover its previous status, "
                                    f"from {alert.event.get('previous_status')} to {alert.event.get('status')}"
                                ),
                            )

                    # Move cursor to last timestamp for next batch
                    last_timestamp = alerts_in_maint[-1].timestamp

                    # If we got less than batch_size, we've processed all alerts
                    if len(alerts_in_maint) < batch_size:
                        break

        for (tenant, fp) in fingerprints_to_check:
            with existed_or_new_session(session) as session:
                last_alert = get_last_alert_by_fingerprint(tenant, fp, session)
                alert = get_alert_by_event_id(tenant, str(last_alert.alert_id), session)
            if "previous_status" not in alert.event:
                logger.info(
                    f"Alert {alert.id} does not have previous status, cannot proceed with recover strategy",
                    extra={"tenant_id": tenant, "fingerprint": fp, "alert_id": alert.id, "alert.status": alert.event.get("status")},
                )
                continue
            if not isinstance(alert.event.get("source"), list):
                alert.event["source"] = [alert.event["source"]]
            alert_dto = AlertDto(**alert.event)
            with tracer.start_as_current_span("mw_recover_strategy_push_to_workflows"):
                try:
                    # Now run any workflow that should run based on this alert
                    # TODO: this should publish event
                    workflow_manager = WorkflowManager.get_instance()
                    # insert the events to the workflow manager process queue
                    logger.info("Adding event to the workflow manager queue")
                    workflow_manager.insert_events(tenant, [alert_dto])
                    logger.info("Added event to the workflow manager queue")
                except Exception:
                    logger.exception(
                        "Failed to run workflows based on alerts",
                        extra={
                            "provider_type": alert_dto.providerType,
                            "provider_id": alert_dto.providerId,
                            "tenant_id": tenant,
                        },
                    )
            incidents = []
            with tracer.start_as_current_span("mw_recover_strategy_run_rules_engine"):
                # Now we need to run the rules engine
                if KEEP_CORRELATION_ENABLED:
                    try:
                        rules_engine = RulesEngine(tenant_id=tenant)
                        # handle incidents, also handle workflow execution as
                        incidents = rules_engine.run_rules(
                            [alert_dto], session=session
                        )
                    except Exception:
                        logger.exception(
                            "Failed to run rules engine",
                            extra={
                                "provider_type": alert_dto.providerType,
                                "provider_id": alert_dto.providerId,
                                "tenant_id": tenant,
                            },
                        )

            with tracer.start_as_current_span("mw_recover_strategy_notify_client"):
                pusher_client = get_pusher_client()
                if not pusher_client:
                    return
                pusher_cache = get_notification_cache()
                if pusher_cache.should_notify(tenant, "poll-alerts"):
                    try:
                        pusher_client.trigger(
                            f"private-{tenant}",
                            "poll-alerts",
                            "{}",
                        )
                        logger.info("Told client to poll alerts")
                    except Exception:
                        logger.exception("Failed to tell client to poll alerts")
                        pass

                if incidents and pusher_cache.should_notify(tenant, "incident-change"):
                    pusher_client = get_pusher_client()
                    try:
                        pusher_client.trigger(
                            f"private-{tenant}",
                            "incident-change",
                            {},
                        )
                    except Exception:
                        logger.exception("Failed to tell the client to pull incidents")

                try:
                    presets = get_all_presets_dtos(tenant)
                    rules_engine = RulesEngine(tenant_id=tenant)
                    presets_do_update = []
                    for preset_dto in presets:
                        # filter the alerts based on the search query
                        filtered_alerts = rules_engine.filter_alerts(
                            [alert_dto], preset_dto.cel_query
                        )
                        # if not related alerts, no need to update
                        if not filtered_alerts:
                            continue
                        presets_do_update.append(preset_dto)
                    if pusher_cache.should_notify(tenant, "poll-presets"):
                        try:
                            pusher_client.trigger(
                                f"private-{tenant}",
                                "poll-presets",
                                json.dumps(
                                    [p.name.lower() for p in presets_do_update], default=str
                                ),
                            )
                        except Exception:
                            logger.exception("Failed to send presets via pusher")
                except Exception:
                    logger.exception(
                        "Failed to send presets via pusher",
                        extra={
                            "provider_type": alert_dto.providerType,
                            "provider_id": alert_dto.providerId,
                            "tenant_id": tenant,
                        },
                    )
        logger.info("Finished recover strategy for maintenance windows review.")