import {
  Button,
  Icon,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeaderCell,
  TableRow,
  DateRangePicker,
  DateRangePickerValue
} from "@tremor/react";
import {
  DisplayColumnDef,
  ExpandedState,
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { MdRemoveCircle, MdModeEdit, MdExpandMore, MdExpandLess } from "react-icons/md";
import { toast } from "react-toastify";
import { MaintenanceRule } from "./model";
import { IoCheckmark } from "react-icons/io5";
import { HiMiniXMark } from "react-icons/hi2";
import { useState, useMemo } from "react";
import { useApi } from "@/shared/lib/hooks/useApi";
import { showErrorToast } from "@/shared/ui";
import React from "react";

const columnHelper = createColumnHelper<MaintenanceRule>();

interface Props {
  maintenanceRules: MaintenanceRule[];
  editCallback: (rule: MaintenanceRule) => void;
}

export default function MaintenanceRulesTable({
  maintenanceRules,
  editCallback,
}: Props) {
  const api = useApi();
  const [expanded, setExpanded] = useState<ExpandedState>({});
  const [inProgress, setInProgress] = useState<boolean>(false);
  const [showFilters, setShowFilters] = useState<boolean>(false);
  const [dateRange, setDateRange] = useState<DateRangePickerValue>({
    from: undefined,
    to: undefined,
  });
  const [collapsed, setCollapsed] = useState({ description: false, cel: false, name: false });  // Estado para colapsar las columnas

  const filteredRules = useMemo(() => {
    const now = new Date();
    return maintenanceRules.filter((rule) => {
      const ruleStart = new Date(rule.start_time + "Z");
      const ruleEnd = new Date(rule.end_time + "Z");

      let dateFilter = true;
      if (showFilters && dateRange.from) {
        const fromDate = new Date(dateRange.from);
        fromDate.setHours(0, 0, 0, 0);
        const toDate = dateRange.to ? new Date(dateRange.to) : new Date(dateRange.from);
        toDate.setHours(23, 59, 59, 999);
        dateFilter = ruleEnd >= fromDate && ruleStart <= toDate;
      }

      const inProgressFilter = inProgress
        ? ruleStart < now && ruleEnd > now && rule.enabled === true
        : true;

      return dateFilter && inProgressFilter;
    });
  }, [maintenanceRules, dateRange, showFilters, inProgress]);

  const columns = [
    columnHelper.display({
      id: "delete",
      header: "",
      cell: (context) => (
        <div className={"space-x-1 flex flex-row items-center justify-center"}>
          <Button
            color="orange"
            size="xs"
            variant="secondary"
            icon={context.row.getIsExpanded() ? MdExpandLess : MdExpandMore}
            onClick={(e: any) => {
              e.preventDefault();
              context.row.toggleExpanded();
            }}
          />
          <Button
            color="orange"
            size="xs"
            variant="secondary"
            icon={MdModeEdit}
            onClick={(e: any) => {
              e.preventDefault();
              editCallback(context.row.original!);
            }}
          />
          <Button
            color="red"
            size="xs"
            variant="secondary"
            icon={MdRemoveCircle}
            onClick={(e: any) => {
              e.preventDefault();
              deleteMaintenanceRule(context.row.original.id!);
            }}
          />
        </div>
      ),
    }),
    columnHelper.display({
      id: "name",
      header: () => (
        <span
          onClick={() => setCollapsed(prev => ({ ...prev, name: !prev.name }))}
          className="cursor-pointer hover:text-orange-600 transition-colors duration-300 underline"
        >
          Name
        </span>
      ),
      cell: ({ row }) => {
        const name = row.original.name;
        return collapsed.name ? name.slice(0, 10) + (name.length > 10 ? '...' : '') : name;
      },
    }),
    columnHelper.display({
      id: "description",
      header: () => (
        <span
          onClick={() => setCollapsed(prev => ({ ...prev, description: !prev.description }))}
          className="cursor-pointer hover:text-orange-600 transition-colors duration-300 underline"
        >
          Description
        </span>
      ),
      cell: (context) => {
        const desc = context.row.original.description;
        return desc
          ? collapsed.description
            ? desc.slice(0, 10) + (desc.length > 10 ? '...' : '')
            : desc
          : "";
      },
    }),
    columnHelper.display({
      id: "start_time",
      header: "Start Time",
      cell: (context) =>
        new Date(context.row.original.start_time + "Z").toLocaleString(),
    }),
    columnHelper.display({
      id: "CEL",
      header: () => (
        <span
          onClick={() => setCollapsed(prev => ({ ...prev, cel: !prev.cel }))}
          className="cursor-pointer hover:text-orange-600 transition-colors duration-300 underline"
        >
          CEL
        </span>
      ),
      cell: (context) => {
        const cel = context.row.original.cel_query;
        return collapsed.cel ? cel.slice(0, 10) + (cel.length > 10 ? '...' : '') : cel;
      },
    }),
    columnHelper.display({
      id: "end_time",
      header: "End Time",
      cell: (context) =>
        context.row.original.end_time
          ? new Date(context.row.original.end_time + "Z").toLocaleString()
          : "N/A",
    }),
    columnHelper.display({
      id: "enabled",
      header: "Enabled",
      cell: (context) => (
        <div>
          {context.row.original.enabled ? (
            <Icon icon={IoCheckmark} size="md" color="orange" />
          ) : (
            <Icon icon={HiMiniXMark} size="md" color="orange" />
          )}
        </div>
      ),
    }),
  ] as DisplayColumnDef<MaintenanceRule>[];

  const table = useReactTable({
    getRowId: (row) => row.id.toString(),
    columns,
    data: filteredRules,
    state: { expanded },
    getCoreRowModel: getCoreRowModel(),
    onExpandedChange: setExpanded,
  });

  const deleteMaintenanceRule = (maintenanceRuleId: number) => {
    if (confirm("Are you sure you want to delete this maintenance rule?")) {
      api
        .delete(`/maintenance/${maintenanceRuleId}`)
        .then(() => {
          toast.success("Maintenance rule deleted successfully");
        })
        .catch((error: any) => {
          showErrorToast(error, "Failed to delete maintenance rule");
        });
    }
  };

  return (
    <div>
      <div className="mb-4">
        <div className="flex justify-center">
          <div
            className="cursor-pointer font-semibold text-lg flex items-center space-x-2 select-none hover:text-orange-600"
             onClick={() => {
              setShowFilters((prev) => {
                if (prev) {
                  toast.dismiss();
                  toast.warn("Hiding filters, showing all maintenance windows...");
                  setInProgress(false);
                  setDateRange({ from: undefined, to: undefined });
                } else {
                  toast.dismiss();
                }
                return !prev;
              });
              }}
          >
            <span className="text-sm">Filter</span>
            <span className={`transition-transform duration-300 ${showFilters ? "rotate-180" : ""}`}>
              <svg width="20" height="20" fill="none" viewBox="0 0 24 24">
                <path d="M6 9l6 6 6-6" stroke="#333" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </span>
          </div>
        </div>
        <div
          className={`overflow-hidden transition-all duration-300 ${showFilters ? "max-h-40 opacity-100" : "max-h-0 opacity-0"}`}
        >
          {showFilters && (
            <div className="flex space-x-16 mt-2 p-4 bg-white rounded-lg shadow-lg border border-gray-200 justify-center items-center">
              <div className="flex flex-row items-center gap-4" onClick={() => setInProgress(false)}>
                <label
                  htmlFor="daterange"
                  className="whitespace-nowrap text-tremor-default font-medium text-tremor-content-strong dark:text-dark-tremor-content-strong"
                >
                  Date Range:
                </label>
                <DateRangePicker
                  value={dateRange}
                  onValueChange={(value) => {
                    setDateRange(value);
                    toast.dismiss();
                    toast.info("Showing maintenance windows for selected date range...");
                  }}
                  id="daterange"
                  className="border-orange-500 dark:border-dark-tremor-border"
                />

              </div>
              <div className="flex items-center space-x-3 w-[300px] justify-between">
                <label
                  htmlFor="inProgress"
                  className="whitespace-nowrap text-tremor-default font-medium text-tremor-content-strong dark:text-dark-tremor-content-strong"
                >
                  Show Maintenance Windows in progress:
                </label>
                <Switch id="inProgress" checked={inProgress} onChange={() => {
                  if (!inProgress) {
                    toast.dismiss();
                    toast.info("Showing in progress maintenance windows...");
                  } else {
                    toast.dismiss();
                    toast.info("Showing all maintenance windows...");
                  }
                  setInProgress((prev) => !prev);
                  if (!inProgress) setDateRange({ from: undefined, to: undefined });
                }} />
              </div>
            </div>
          )}
        </div>
      </div>
      <style>{`
        .tremor-Table-root {
          overflow: visible !important;
        }
        .sticky-header thead {
          position: sticky;
          top: 0;
          background: white;
          z-index: 20;
          box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .dark .sticky-header thead {
          background: rgb(31 41 55); /* bg-gray-900 */
        }
      `}</style>
      <div className="max-h-[80vh] overflow-y-auto">
        <Table className="sticky-header">
          <TableHead suppressHydrationWarning={true}>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow
                className="border-b border-tremor-border dark:border-dark-tremor-border"
                key={headerGroup.id}
              >
                {headerGroup.headers.map((header) => (
                  <TableHeaderCell
                    className="text-tremor-content-strong dark:text-dark-tremor-content-strong"
                    key={header.id}
                  >
                    {flexRender(
                      header.column.columnDef.header,
                      header.getContext()
                    )}
                  </TableHeaderCell>
                ))}
              </TableRow>
            ))}
          </TableHead>
          <TableBody>
            {table.getRowModel().rows.map((row) => (
              <React.Fragment key={row.id}>
                <TableRow
                  className="even:bg-tremor-background-muted even:dark:bg-dark-tremor-background-muted hover:bg-slate-100"
                  key={row.id}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
                {row.getIsExpanded() && (
                  <TableRow className="pl-2.5" key={`${row.id}-expanded`}>
                    <TableCell colSpan={columns.length}>
                      <div className="flex space-x-2 divide-x">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold">Created By:</span>
                          <span>{row.original.created_by}</span>
                        </div>
                        {row.original.updated_at && (
                          <>
                            <div className="flex items-center space-x-2 pl-2.5">
                              <span className="font-bold">Updated At:</span>
                              <span>
                                {new Date(
                                  row.original.updated_at + "Z"
                                ).toLocaleString()}
                              </span>
                            </div>
                            <div className="flex items-center space-x-2 pl-2.5">
                              <span className="font-bold">Show in the Feed:</span>
                              <span>{row.original.suppress ? "Yes" : "No"}</span>
                            </div>
                            <div className="flex items-center space-x-2 pl-2.5">
                              <span className="font-bold">Status ignored:</span>
                              <span>{row.original.ignore_statuses.length > 0 ? row.original.ignore_statuses.join(', ') : 'None'}</span>
                            </div>
                          </>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </React.Fragment>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
