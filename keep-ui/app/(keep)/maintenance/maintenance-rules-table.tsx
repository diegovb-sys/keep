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
  TextInput,
  Text
} from "@tremor/react";
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
  const [startDate, setStartDate] = useState<string>(new Date().toISOString().slice(0, 10));
  const [endDate, setEndDate] = useState<string>(new Date().toISOString().slice(0, 10));
  const [onlyEnabled, setIsEnabled] = useState<boolean>(false);
  const [showFilters, setShowFilters] = useState<boolean>(false);

  const filteredRules = useMemo(() => {
    return maintenanceRules.filter((rule) => {
      const ruleDate = new Date(rule.start_time + "Z");
      const afterStart = showFilters ? (startDate ? ruleDate >= new Date(startDate) : true) : true;
      const beforeEnd = showFilters ? (endDate ? ruleDate <= new Date(endDate) : true) : true;
      const isEnabled = onlyEnabled ? rule.enabled : true;
      return afterStart && beforeEnd && isEnabled;
    });
  }, [maintenanceRules, startDate, endDate, onlyEnabled, showFilters]);

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
            onClick={() => setShowFilters((prev) => !prev)}
          >
            <span className="text-sm">Filter</span>
            <span className={`transition-transform duration-300 ${showFilters ? "rotate-180" : ""}`}>
              <svg width="20" height="20" fill="none" viewBox="0 0 24 24">
                <path d="M6 9l6 6 6-6" stroke="#333" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </span>
          </div>
        </div>
        <div
          className={`overflow-hidden transition-all duration-300 ${showFilters ? "max-h-40 opacity-100" : "max-h-0 opacity-0"}`}
        >
          {showFilters && (
            <div className="flex space-x-4 mt-2 p-4 bg-white rounded-lg shadow-lg border border-gray-200">
               <div className="flex flex-col items-center">
               <Text className="mb-1">Start date:</Text>
              <TextInput
                type={"date" as any}
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="w-40"
                placeholder="Start Date"
              />
              </div>
              <div className="flex flex-col items-center">
               <Text className="mb-1">End date:</Text>
              <TextInput
                type={"date" as any}
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="w-40"
                placeholder="End Date"
              />
              </div>

      <div className="flex items-center space-x-3 mt-2.5 w-[300px] justify-between">
        <label
          htmlFor="onlyEnabledSwitch"
          className="text-tremor-default text-tremor-content dark:text-dark-tremor-content"
        >
          Show only Enabled:
        </label>
        <Switch id="onlyEnabledSwitch" checked={onlyEnabled} onChange={setIsEnabled} />
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
