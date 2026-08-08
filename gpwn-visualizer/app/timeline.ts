export function timelineRatio(time: number, duration: number) {
  if (!Number.isFinite(time) || !Number.isFinite(duration) || duration <= 0) {
    return 0;
  }
  return Math.max(0, Math.min(1, time / duration));
}

export function timelinePercent(time: number, duration: number) {
  return `${timelineRatio(time, duration) * 100}%`;
}

export function playbackStart(time: number | null, duration: number) {
  if (!Number.isFinite(duration) || duration <= 0) return 0;
  if (time === null || !Number.isFinite(time) || time >= duration) return 0;
  return Math.max(0, time);
}

export function playbackTime(start: number, elapsedMilliseconds: number, speed: number, duration: number) {
  if (![start, elapsedMilliseconds, speed, duration].every(Number.isFinite) || duration <= 0) return 0;
  return Math.max(0, Math.min(duration, start + (elapsedMilliseconds / 1000) * Math.max(0, speed)));
}
