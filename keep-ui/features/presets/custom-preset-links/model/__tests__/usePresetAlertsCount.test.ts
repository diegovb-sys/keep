import { renderHook } from "@testing-library/react";
import { usePresetAlertsCount } from "../usePresetAlertsCount";
import { useAlerts } from "@/entities/alerts/model/useAlerts";
import { useConfig } from "@/utils/hooks/useConfig";
import { useSearchParams } from "next/navigation";

jest.mock("@/entities/alerts/model/useAlerts");
jest.mock("@/utils/hooks/useConfig");
jest.mock("next/navigation", () => ({
  useSearchParams: jest.fn(),
}));

const mockUseLastAlerts = jest.fn();
const mockSearchParams = {
  get: jest.fn(),
};

beforeEach(() => {
  jest.clearAllMocks();
  (useAlerts as jest.Mock).mockReturnValue({
    useLastAlerts: mockUseLastAlerts,
  });
  mockUseLastAlerts.mockReturnValue({
    data: [],
    totalCount: 0,
    isLoading: false,
    mutate: jest.fn(),
  });
  (useSearchParams as jest.Mock).mockReturnValue(mockSearchParams);
  mockSearchParams.get.mockReturnValue(null);
});

describe("usePresetAlertsCount", () => {
  it("should include timestamp filter when KEEP_CUSTOM_DATE_DAYS_FILTER is configured (no URL params)", () => {
    (useConfig as jest.Mock).mockReturnValue({
      data: { KEEP_CUSTOM_DATE_DAYS_FILTER: "30" },
    });
    mockSearchParams.get.mockReturnValue(null); // No URL params

    renderHook(() =>
      usePresetAlertsCount("severity == 'critical'", true, 0, 0)
    );

    expect(mockUseLastAlerts).toHaveBeenCalled();

    const callArg = mockUseLastAlerts.mock.calls[0][0];
    expect(callArg.cel).toContain("status == 'firing'");
    expect(callArg.cel).toContain("timestamp >=");
    expect(callArg.cel).toContain("severity == 'critical'");
  });

  it("should NOT include timestamp filter when KEEP_CUSTOM_DATE_DAYS_FILTER is not configured (all-time)", () => {
    (useConfig as jest.Mock).mockReturnValue({
      data: { KEEP_CUSTOM_DATE_DAYS_FILTER: undefined },
    });

    renderHook(() =>
      usePresetAlertsCount("severity == 'critical'", true, 0, 0)
    );

    const callArg = mockUseLastAlerts.mock.calls[0][0];
    expect(callArg.cel).toContain("status == 'firing'");
    expect(callArg.cel).not.toContain("timestamp >=");
    expect(callArg.cel).toContain("severity == 'critical'");
  });

  it("should include timestamp filter when counterShowsFiringOnly is false", () => {
    (useConfig as jest.Mock).mockReturnValue({
      data: { KEEP_CUSTOM_DATE_DAYS_FILTER: "7" },
    });

    renderHook(() =>
      usePresetAlertsCount("severity == 'critical'", false, 0, 0)
    );

    const callArg = mockUseLastAlerts.mock.calls[0][0];
    expect(callArg.cel).not.toContain("status == 'firing'");
    expect(callArg.cel).toContain("timestamp >=");
    expect(callArg.cel).toContain("severity == 'critical'");
  });

  it("should handle empty preset CEL with config", () => {
    (useConfig as jest.Mock).mockReturnValue({
      data: { KEEP_CUSTOM_DATE_DAYS_FILTER: "30" },
    });

    renderHook(() => usePresetAlertsCount("", false, 0, 0));

    const callArg = mockUseLastAlerts.mock.calls[0][0];
    expect(callArg.cel).toContain("timestamp >=");
    expect(callArg.cel).not.toContain("status == 'firing'");
  });

  it("should handle empty preset CEL without config (all-time)", () => {
    (useConfig as jest.Mock).mockReturnValue({
      data: { KEEP_CUSTOM_DATE_DAYS_FILTER: undefined },
    });
    mockSearchParams.get.mockReturnValue(null);

    renderHook(() => usePresetAlertsCount("", false, 0, 0));

    const callArg = mockUseLastAlerts.mock.calls[0][0];
    // Should have no filters, effectively all-time
    expect(callArg.cel).toBe("");
  });

  it("should read timeFrame from URL params (relative 1h)", () => {
    (useConfig as jest.Mock).mockReturnValue({
      data: { KEEP_CUSTOM_DATE_DAYS_FILTER: "30" }, // Config says 30 days
    });
    // Mock URL params for 1h
    mockSearchParams.get.mockImplementation((key: string) => {
      if (key === "timeFrameType") return "relative";
      if (key === "deltaMs") return String(60 * 60 * 1000); // 1h in ms
      if (key === "isPaused") return "false";
      return null;
    });

    renderHook(() =>
      usePresetAlertsCount("severity == 'critical'", true, 0, 0)
    );

    const callArg = mockUseLastAlerts.mock.calls[0][0];
    expect(callArg.cel).toContain("status == 'firing'");
    expect(callArg.cel).toContain("timestamp >=");
    expect(callArg.cel).toContain("severity == 'critical'");
    // The timestamp should be ~1h ago, not 30 days
  });

  it("should read timeFrame from URL params (absolute range)", () => {
    (useConfig as jest.Mock).mockReturnValue({
      data: { KEEP_CUSTOM_DATE_DAYS_FILTER: "30" },
    });
    const start = new Date("2026-03-01T00:00:00Z").getTime();
    const end = new Date("2026-03-02T00:00:00Z").getTime();

    mockSearchParams.get.mockImplementation((key: string) => {
      if (key === "timeFrameType") return "absolute";
      if (key === "startDate") return String(start);
      if (key === "endDate") return String(end);
      return null;
    });

    renderHook(() =>
      usePresetAlertsCount("severity == 'critical'", true, 0, 0)
    );

    const callArg = mockUseLastAlerts.mock.calls[0][0];
    expect(callArg.cel).toContain("status == 'firing'");
    expect(callArg.cel).toContain("timestamp >=");
    expect(callArg.cel).toContain("timestamp <=");
    expect(callArg.cel).toContain("severity == 'critical'");
  });
});
