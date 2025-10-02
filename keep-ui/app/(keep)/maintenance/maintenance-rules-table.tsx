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
import { RiWifiLine } from '@remixicon/react';
import {
  DisplayColumnDef,
  ExpandedState,
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { MdRemoveCircle, MdModeEdit } from "react-icons/md";
import { toast } from "react-toastify";
import { MaintenanceRule } from "./model";
import { IoCheckmark } from "react-icons/io5";
import { HiMiniXMark } from "react-icons/hi2";
import { useState, useMemo } from "react";
import { useApi } from "@/shared/lib/hooks/useApi";
import { showErrorToast } from "@/shared/ui";
import { on } from "events";

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
      header: "Name",
      cell: ({ row }) => row.original.name,
    }),
    columnHelper.display({
      id: "description",
      header: "Description",
      cell: (context) => context.row.original.description,
    }),
    columnHelper.display({
      id: "start_time",
      header: "Start Time",
      cell: (context) =>
        new Date(context.row.original.start_time + "Z").toLocaleString(),
    }),
    columnHelper.display({
      id: "CEL",
      header: "CEL",
      cell: (context) => context.row.original.cel_query,
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
      <Table>
        <TableHead>
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
            <>
              <TableRow
                className="even:bg-tremor-background-muted even:dark:bg-dark-tremor-background-muted hover:bg-slate-100"
                key={row.id}
                onClick={() => row.toggleExpanded()}
              >
                {row.getVisibleCells().map((cell) => (
                  <TableCell key={cell.id}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </TableCell>
                ))}
              </TableRow>
              {row.getIsExpanded() && (
                <TableRow className="pl-2.5">
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
                            <span className="font-bold">Enabled:</span>
                            <span>{row.original.enabled ? "Yes" : "No"}</span>
                          </div>
                        </>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              )}
            </>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
