import re

from keep.api.models.alert import AlertSeverity
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


def normalize_cel_expression(cel_expression: QueryDto, logger) -> QueryDto:
    """
        Normalize CEL expression by setting defaults for limit, offset, and sort options.

        Args:
            cel_expression (QueryDto): The CEL expression payload.
            logger: Logger instance for logging warnings.

        Note:
            Shahar: this happens when the frontend query builder fails to build a query
    """
    query_with_defaults = cel_expression.copy()
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
