import { describe, expect, test } from "bun:test";
import { playbackStart, playbackTime, timelinePercent, timelineRatio } from "../app/timeline";

describe("timeline coordinates", () => {
  test("maps capture time to one shared normalized track", () => {
    expect(timelineRatio(0, 120)).toBe(0);
    expect(timelineRatio(30, 120)).toBe(0.25);
    expect(timelineRatio(60, 120)).toBe(0.5);
    expect(timelineRatio(120, 120)).toBe(1);
  });

  test("clamps markers and playhead to the same endpoints", () => {
    expect(timelinePercent(-4, 120)).toBe("0%");
    expect(timelinePercent(60, 120)).toBe("50%");
    expect(timelinePercent(125, 120)).toBe("100%");
    expect(timelinePercent(10, 0)).toBe("0%");
  });

  test("restarts from zero at the end and advances at the selected speed", () => {
    expect(playbackStart(null, 120)).toBe(0);
    expect(playbackStart(120, 120)).toBe(0);
    expect(playbackStart(30, 120)).toBe(30);
    expect(playbackTime(30, 2_000, 4, 120)).toBe(38);
    expect(playbackTime(118, 2_000, 4, 120)).toBe(120);
  });
});
