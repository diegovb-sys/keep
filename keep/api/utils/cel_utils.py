import json
import logging
import re
from typing import List

import celpy

from keep.api.models.alert import AlertDto, AlertSeverity
from keep.api.models.db.rule import Rule
from keep.api.models.query import QueryDto, SortOptionsDto


def preprocess_cel_expression(cel_expression: str) -> str:
    """Preprocess CEL expressions to replace string-based comparisons with numeric values where applicable."""

    # Construct a regex pattern that matches any severity level or other comparisons
    # and accounts for both single and double quotes as well as optional spaces around the operator
    severities = "|".join(
        [f"\"{severity.value}\"|'{severity.value}'" for severity in AlertSeverity]
    )
    pattern = rf"(\w+)\s*([=><!]=?)\s*({severities})"

    def replace_matched(match):
        field_name, operator, matched_value = (
            match.group(1),
            match.group(2),
            match.group(3).strip("\"'"),
        )

        # Handle severity-specific replacement
        if field_name.lower() == "severity":
            severity_order = next(
                (
                    severity.order
                    for severity in AlertSeverity
                    if severity.value == matched_value.lower()
                ),
                None,
            )
            if severity_order is not None:
                return f"{field_name} {operator} {severity_order}"

        # Return the original match if it's not a severity comparison or if no replacement is necessary
        return match.group(0)

    modified_expression = re.sub(
        pattern, replace_matched, cel_expression, flags=re.IGNORECASE
    )

    return modified_expression


def replace_none_as_null(data):
    if isinstance(data, dict):
        return {k: replace_none_as_null(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [replace_none_as_null(v) for v in data]
    elif data is None:
        return ""
    return data


def normalize_cel_expression(cel_expression: QueryDto, logger: logging.Logger, skip_fields: list = []) -> QueryDto:
    """
        Normalize CEL expression by setting defaults for limit, offset, and sort options.

        Args:
            cel_expression (QueryDto): The CEL expression payload.
            logger: Logger instance for logging warnings.

        Note:
            Shahar: this happens when the frontend query builder fails to build a query
    """
    query_with_defaults = cel_expression.copy()
    if skip_fields:
        for field in skip_fields:
            if query_with_defaults.cel and field in query_with_defaults.cel:
                logger.info(f"Skipping field {field} in CEL expression normalization {query_with_defaults.cel}")
                query_with_defaults.cel = re.sub(rf"{field}.*[a-zA-Z0-9\"]+", 'true==true', query_with_defaults.cel)
    if query_with_defaults.cel == "1 == 1":
        logger.warning("Failed to build query for alerts")
        query_with_defaults.cel = ""
    if query_with_defaults.limit is None:
        query_with_defaults.limit = 1000
    if query_with_defaults.offset is None:
        query_with_defaults.offset = 0
    if query_with_defaults.sort_by is not None:
        query_with_defaults.sort_options = [
            SortOptionsDto(
                sort_by=query_with_defaults.sort_by,
                sort_dir=query_with_defaults.sort_dir,
            )
        ]
    if not query_with_defaults.sort_options:
        query_with_defaults.sort_options = [
            SortOptionsDto(sort_by="timestamp", sort_dir="desc")
        ]
    return query_with_defaults


def extract_subrules(expression):
    # CEL rules looks like '(source == "sentry") || (source == "grafana" && severity == "critical")'
    # and we need to extract the subrules
    sub_rules = expression.split(") || (")
    if len(sub_rules) == 1:
        return sub_rules
    # the first and the last rules will have a ( or ) at the beginning or the end
    # e.g. for the example of:
    #           (source == "sentry") && (source == "grafana" && severity == "critical")
    # than sub_rules[0] will be (source == "sentry" and sub_rules[-1] will be source == "grafana" && severity == "critical")
    # so we need to remove the first and last character
    sub_rules[0] = sub_rules[0][1:]
    sub_rules[-1] = sub_rules[-1][:-1]
    return sub_rules


def sanitize_cel_payload(payload):
    """
    Remove keys containing forbidden characters from payload and return warnings.
    Returns tuple of (sanitized_payload, warnings)
    """
    forbidden_starts = [
        "@",
        "-",
        "$",
        "#",
        " ",
        ":",
        ".",
        "/",
        "\\",
        "*",
        "&",
        "^",
        "%",
        "!",
    ]
    logger = logging.getLogger(__name__)

    def _sanitize_dict(d):
        result = {}
        for k, v in d.items():
            if k[0] in forbidden_starts:  # Only check first character
                logger.warning(
                    f"Removed key '{k}' starting with forbidden character '{k[0]}'"
                )
                continue

            if isinstance(v, dict):
                result[k] = _sanitize_dict(v)
            elif isinstance(v, list):
                result[k] = [
                    _sanitize_dict(i) if isinstance(i, dict) else i for i in v
                ]
            else:
                result[k] = v
        return result

    sanitized = _sanitize_dict(payload)
    return sanitized

def check_if_rule_apply(rule: [Rule | QueryDto], event: AlertDto, environment: celpy.Environment) -> List[str]:
    """
    Evaluates if a rule applies to an event using CEL. Handles type coercion for ==/!= between int and str.
    """
    if isinstance(rule, QueryDto):
        sub_rules = extract_subrules(rule.cel)
    else:
        sub_rules = extract_subrules(rule.definition_cel)
    payload = event.dict()
    # workaround since source is a list
    # todo: fix this in the future
    payload["source"] = payload["source"][0]
    payload = sanitize_cel_payload(payload)

    # what we do here is to compile the CEL rule and evaluate it
    #   https://github.com/cloud-custodian/cel-python
    #   https://github.com/google/cel-spec
    sub_rules_matched = []
    for sub_rule in sub_rules:
        # Shahar: rules such as "(source != null)" causing an exception:
        #           celpy.evaluation.CELEvalError: ("found no matching overload for 'relation_ne' applied to
        #           '(<class 'celpy.celtypes.StringType'>, <class 'NoneType'>)'", <class 'TypeError'>,
        #            ("no such overload:  <class 'celpy.celtypes.StringType'> != None <class 'NoneType'>",))
        #          So we need to replace "null" with ""
        #
        #          TODO: it works for strings now, but we need to add support on list/dict when needed
        if "null" in sub_rule:
            sub_rule = sub_rule.replace("null", '""')
            activation = celpy.json_to_cel(json.loads(json.dumps(replace_none_as_null(payload), default=str)))
        else:
            activation = celpy.json_to_cel(json.loads(json.dumps(payload, default=str)))
        ast = environment.compile(sub_rule)
        prgm = environment.program(ast)
        try:
            r = prgm.evaluate(activation)
        except celpy.evaluation.CELEvalError as e:
            # this is ok, it means that the subrule is not relevant for this event
            if "no such member" in str(e):
                continue
            # unknown
            # --- Fix for https://github.com/keephq/keep/issues/5107 ---
            if "no such overload" in str(e) or "found no matching overload" in str(
                e
            ):
                try:
                    coerced = coerce_eq_type_error(
                        sub_rule, prgm, activation, event
                    )
                    if coerced:
                        sub_rules_matched.append(sub_rule)
                        continue
                except Exception:
                    pass
            raise
        if r:
            sub_rules_matched.append(sub_rule)
    # no subrules matched
    return sub_rules_matched


def coerce_eq_type_error(cel, prgm, activation, alert):
    """
    Helper for type coercion fallback for ==/!= between int and str in CEL.
    Fixes https://github.com/keephq/keep/issues/5107
    """
    import re

    m = re.match(r"([a-zA-Z0-9_\.]+)\s*([!=]=)\s*(.+)", cel)
    if not m:
        return False
    left, op, right = m.groups()
    left = left.strip()
    right = (
        right.strip().strip('"')
        if right.strip().startswith('"') and right.strip().endswith('"')
        else right.strip()
    )
    try:

        def get_nested(d, path):
            for part in path.split("."):
                if isinstance(d, dict):
                    d = d.get(part)
                else:
                    return None
            return d

        left_val = get_nested(activation, left)
        try:
            right_val = int(right)
        except Exception:
            try:
                right_val = float(right)
            except Exception:
                right_val = right
        # If one is str and the other is int/float, compare as str
        if (isinstance(left_val, (int, float)) and isinstance(right_val, str)) or (
            isinstance(left_val, str) and isinstance(right_val, (int, float))
        ):
            if op == "==":
                return str(left_val) == str(right_val)
            else:
                return str(left_val) != str(right_val)
        # Also handle both as str for robustness
        if op == "==":
            return str(left_val) == str(right_val)
        else:
            return str(left_val) != str(right_val)
    except Exception:
        pass
    return False