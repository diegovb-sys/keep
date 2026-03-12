import { useAlerts } from "@/entities/alerts/model/useAlerts";
import { useEffect, useMemo } from "react";
import { useConfig } from "@/utils/hooks/useConfig";
import { ONE_DAY, TimeFrameV2 } from "@/components/ui/DateRangePickerV2";
import { useSearchParams } from "next/navigation";

function getDateRangeCelFromTimeFrame(timeFrame: TimeFrameV2 | null): string | null {
  if (timeFrame === null) {
    return null;
  }

  if (timeFrame.type === "relative") {
    return `timestamp >= '${new Date(
      new Date().getTime() - timeFrame.deltaMs
    ).toISOString()}'`;
  } else if (timeFrame.type === "absolute") {
    return [
      `timestamp >= '${timeFrame.start.toISOString()}'`,
      `timestamp <= '${timeFrame.end.toISOString()}'`,
    ].join(" && ");
  }

  return null; // all-time
}

export const usePresetAlertsCount = (
  presetCel: string,
  counterShowsFiringOnly: boolean,
  limit = 0,
  offset = 0,
  refreshInterval: number | undefined = undefined
) => {
  const { useLastAlerts } = useAlerts();
  const { data: appConfig } = useConfig();
  const searchParams = useSearchParams();

  // Get the default time filter from config (same as alert-table-server-side.tsx)
  const days = appConfig?.KEEP_CUSTOM_DATE_DAYS_FILTER;

  // Read timeFrame from URL params (synced with the UI date picker)
  const currentTimeFrame = useMemo((): TimeFrameV2 | null => {
    const type = searchParams.get("timeFrameType");

    if (!type) {
      // No query params, use default from config
      if (days) {
        return {
          type: "relative",
          deltaMs: Number(days) * ONE_DAY,
          isPaused: false,
        };
      }
      return { type: "all-time", isPaused: false };
    }

    switch (type) {
      case "absolute": {
        const startDate = Number.parseInt(searchParams.get("startDate") as string);
        const endDate = Number.parseInt(searchParams.get("endDate") as string);
        if (!startDate || !endDate) break;
        return {
          type: "absolute",
          start: new Date(startDate),
          end: new Date(endDate),
        };
      }
      case "relative": {
        const deltaMs = Number.parseInt(searchParams.get("deltaMs") as string);
        if (!deltaMs) break;
        const isPaused = searchParams.get("isPaused") === "true";
        return {
          type: "relative",
          deltaMs,
          isPaused,
        };
      }
      case "all-time": {
        return {
          type: "all-time",
          isPaused: searchParams.get("isPaused") === "true",
        };
      }
    }

    // Fallback
    if (days) {
      return {
        type: "relative",
        deltaMs: Number(days) * ONE_DAY,
        isPaused: false,
      };
    }
    return { type: "all-time", isPaused: false };
  }, [searchParams, days]);

  const dateRangeCel = useMemo(() => {
    return getDateRangeCelFromTimeFrame(currentTimeFrame);
  }, [currentTimeFrame]);

  const celList = [];

  if (counterShowsFiringOnly) {
    celList.push("status == 'firing'");
  }

  // Add the timestamp filter only if configured
  if (dateRangeCel) {
    celList.push(dateRangeCel);
  }

  celList.push(presetCel);

  const { data, totalCount, isLoading, mutate } = useLastAlerts({
    cel: celList
      .filter((cel) => !!cel)
      .map((cel) => `(${cel})`)
      .join(" && "),
    limit: limit,
    offset: offset,
  });

  useEffect(() => {
    if (!refreshInterval) {
      return;
    }

    const intervalId = setInterval(() => mutate(), refreshInterval);
    return () => clearInterval(intervalId);
  }, [refreshInterval]);

  return { alerts: data, totalCount, isLoading };
};
