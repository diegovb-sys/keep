import { Preset, useSilencedPresets } from "@/entities/presets/model";
import { useMemo } from "react";
import { useApi } from "@/shared/lib/hooks/useApi";
import useSWR from "swr";
import { AlertsQuery } from "@/entities/alerts/model";
import { useConfig } from "@/utils/hooks/useConfig";
import { ONE_DAY, TimeFrameV2 } from "@/components/ui/DateRangePickerV2";
import { useSearchParams } from "next/navigation";
// Using dynamic import to avoid hydration issues with react-player
import dynamic from "next/dynamic";
import clsx from "clsx";
const ReactPlayer = dynamic(() => import("react-player"), { ssr: false });

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

interface PresetsNoiseProps {
  presets: Preset[];
}

export const PresetsNoise = ({ presets }: PresetsNoiseProps) => {
  const api = useApi();
  const { silencedPresetIds } = useSilencedPresets();
  const { data: appConfig } = useConfig();
  const searchParams = useSearchParams();

  const noisyPresets = useMemo(
    () => presets?.filter((preset) => preset.is_noisy && !silencedPresetIds.includes(preset.id)),
    [presets, silencedPresetIds]
  );

  // Get the default time filter from config
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

  const { data: shouldDoNoise } = useSWR(
    () =>
      api.isReady() && noisyPresets
        ? noisyPresets.map((noisyPreset) => noisyPreset.id)
        : null,
    async () => {
      let shouldDoNoise = false;

      // Iterate through noisy presets and find first that has an Alert that should trigger noise
      for (let noisyPreset of noisyPresets) {
        const noisyAlertsCelRules = [
          "status == 'firing' && deleted == false && dismissed == false",
          ...(dateRangeCel ? [dateRangeCel] : []),
          noisyPreset.options.find((opt) => opt.label == "CEL")?.value,
        ];
        const query: AlertsQuery = {
          cel: noisyAlertsCelRules.filter((cel) => !!cel).map((cel) => `(${cel})`).join(" && "),
          limit: 0,
          offset: 0,
        };

        const { count: matchingAlertsCount } = await api.post(
          "/alerts/query",
          query
        );
        shouldDoNoise = !!matchingAlertsCount;

        if (shouldDoNoise) {
          break;
        }
      }

      return shouldDoNoise;
    },
    {
      refreshInterval: 5000, // Refresh every 5 seconds to check if alerts have been resolved
      revalidateOnFocus: true,
      revalidateOnReconnect: true,
    }
  );

  /* React Player for playing alert sound */
  return (
    <div
      data-testid="noisy-presets-audio-player"
      className={clsx("absolute -z-10", {
        playing: shouldDoNoise,
      })}
    >
      <ReactPlayer
        // TODO: cache the audio file fiercely
        url="/music/alert.mp3"
        playing={shouldDoNoise}
        volume={0.5}
        loop={true}
        width="0"
        height="0"
        playsinline
        className="absolute -z-10"
      />
    </div>
  );
};
