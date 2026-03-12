import {
  Button,
  Icon,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeaderCell,
  TableRow,
  Switch,
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
  const [showAll, setShowAll] = useState(false);

  // Filter rules: by default show only active/upcoming windows
  const filteredRules = useMemo(() => {
    if (showAll) return maintenanceRules;

    const now = new Date();
    return maintenanceRules.filter(rule => {
      // Show if enabled and hasn't ended yet (or has no end time)
      if (!rule.enabled) return false;
      if (!rule.end_time) return true;

      const endTime = new Date(rule.end_time + "Z");
      return endTime > now;
    });
  }, [maintenanceRules, showAll]);

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
      cell: (context) => {
        const cel = context.row.original.cel_query;
        const maxLength = 50;
        if (cel.length > maxLength) {
          return (
            <span title={cel} className="cursor-help">
              {cel.substring(0, maxLength)}...
            </span>
          );
        }
        return cel;
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

  const hiddenCount = maintenanceRules.length - filteredRules.length;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <span className="text-sm text-gray-600 dark:text-gray-400">
            Showing {filteredRules.length} of {maintenanceRules.length} rules
          </span>
          {hiddenCount > 0 && !showAll && (
            <span className="text-xs text-orange-600 dark:text-orange-400">
              ({hiddenCount} inactive/past rules hidden)
            </span>
          )}
        </div>
        <div className="flex items-center space-x-2">
          <label className="text-sm text-gray-600 dark:text-gray-400">
            Show all rules
          </label>
          <Switch
            checked={showAll}
            onChange={setShowAll}
          />
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
                  <div className="flex flex-col space-y-2">
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
                    <div className="flex flex-col space-y-1">
                      <span className="font-bold">CEL Query:</span>
                      <pre className="text-xs bg-gray-50 dark:bg-gray-800 p-2 rounded overflow-x-auto">
                        {row.original.cel_query}
                      </pre>
                    </div>
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
