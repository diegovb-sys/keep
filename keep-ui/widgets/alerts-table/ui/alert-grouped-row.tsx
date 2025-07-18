import { TableRow, TableCell } from "@tremor/react";
import { AlertDto } from "@/entities/alerts/model";
import { Table, flexRender, Row } from "@tanstack/react-table";
import { ChevronDownIcon } from "@heroicons/react/24/outline";
import clsx from "clsx";
import { useEffect } from "react";
import { getCommonPinningStylesAndClassNames } from "@/shared/ui";
import { RowStyle } from "@/entities/alerts/model/useAlertRowStyle";
import {
  getRowClassName,
  getCellClassName,
} from "@/widgets/alerts-table/lib/alert-table-utils";

interface GroupedRowProps {
  row: Row<AlertDto>;
  table: Table<AlertDto>;
  theme: Record<string, string>;
  onRowClick?: (e: React.MouseEvent, alert: AlertDto) => void;
  lastViewedAlert: string | null;
  rowStyle: RowStyle;
  isExpanded?: boolean;
  onToggleExpanded?: (groupKey: string) => void;
  onGroupInitialized?: (groupKey: string) => void;
}

export const GroupedRow = ({
  row,
  table,
  theme,
  onRowClick,
  lastViewedAlert,
  rowStyle,
  isExpanded = true,
  onToggleExpanded,
  onGroupInitialized,
}: GroupedRowProps) => {
  const groupKey = row.id;

  // Initialize the group when component mounts
  useEffect(() => {
    if (onGroupInitialized && row.getIsGrouped()) {
      onGroupInitialized(groupKey);
    }
  }, [groupKey, onGroupInitialized, row]);

  if (row.getIsGrouped()) {
    const groupingColumnId = row.groupingColumnId;

    let groupValue = groupingColumnId
      ? row.getValue(groupingColumnId)
      : "Unknown Group";

    if (groupingColumnId === "incident") {
      const incidentsDto = row.original.incident_dto;
      const incidentIds = row.getValue(groupingColumnId);
      if (!incidentIds || incidentIds === "undefined") {
        groupValue = "No Incidents";
      } else {
        groupValue = incidentsDto
          ?.map((incident) => {
            return incident.user_generated_name || incident.ai_generated_name;
          })
          .join(", ");
      }
    }

    return (
      <>
        {/* Group Header Row */}
        <TableRow className="bg-orange-100 hover:bg-orange-200 cursor-pointer border-t border-orange-300">
          {/* Render a single cell that spans the entire width */}
          <TableCell
            colSpan={row.getVisibleCells().length}
            onClick={() => onToggleExpanded?.(groupKey)}
            className="group-header-cell bg-orange-100 group-hover:bg-orange-200"
          >
            <div className="flex items-center gap-2">
              <ChevronDownIcon
                className={clsx(
                  "w-5 h-5 transition-transform",
                  !isExpanded && "-rotate-90"
                )}
              />
              <span className="font-medium">{String(groupValue)}</span>
              <span className="text-gray-500 text-sm">
                ({row.subRows.length}{" "}
                {row.subRows.length === 1 ? "alert" : "alerts"})
              </span>
            </div>
          </TableCell>
        </TableRow>

        {/* Child Rows */}
        {isExpanded &&
          row.subRows.map((subRow) => {
            const isLastViewed =
              subRow.original.fingerprint === lastViewedAlert;

            return (
              <TableRow
                key={subRow.id}
                className={getRowClassName(
                  subRow,
                  theme,
                  lastViewedAlert,
                  rowStyle
                )}
                onClick={(e) => onRowClick?.(e, subRow.original)}
              >
                {subRow.getVisibleCells().map((cell) => {
                  const { style, className } =
                    getCommonPinningStylesAndClassNames(
                      cell.column,
                      table.getState().columnPinning.left?.length,
                      table.getState().columnPinning.right?.length
                    );

                  return (
                    <TableCell
                      key={cell.id}
                      className={getCellClassName(
                        cell,
                        className,
                        rowStyle,
                        isLastViewed
                      )}
                      style={style}
                    >
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext()
                      )}
                    </TableCell>
                  );
                })}
              </TableRow>
            );
          })}
      </>
    );
  }

  // Regular non-grouped row
  const isLastViewed = row.original.fingerprint === lastViewedAlert;

  return (
    <TableRow
      id={`alert-row-${row.original.fingerprint}`}
      key={row.id}
      className={getRowClassName(row, theme, lastViewedAlert, rowStyle)}
      onClick={(e) => onRowClick?.(e, row.original)}
    >
      {row.getVisibleCells().map((cell) => {
        const { style, className } = getCommonPinningStylesAndClassNames(
          cell.column,
          table.getState().columnPinning.left?.length,
          table.getState().columnPinning.right?.length
        );

        return (
          <TableCell
            key={cell.id}
            className={getCellClassName(
              cell,
              className,
              rowStyle,
              isLastViewed
            )}
            style={style}
          >
            {flexRender(cell.column.columnDef.cell, cell.getContext())}
          </TableCell>
        );
      })}
    </TableRow>
  );
};
