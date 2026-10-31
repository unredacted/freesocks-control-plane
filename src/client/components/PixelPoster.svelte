<script lang="ts">
  /**
   * The home page's poster: a pixel-lettered title plate over a small pixel
   * scene (the brand star with an ordered-dither glow, on a night sky). Fixed
   * colors, since it is artwork rather than UI chrome, and purely decorative
   * (aria-hidden): the headline next to it says the same thing in words.
   *
   * The scene is drawn on a 40x43 grid as one SVG path per color with
   * crispEdges, so it stays sharp at any size.
   */
  const W = 40;
  const H = 43;
  const STAR_X = 12;
  const STAR_Y = 11;
  // The eight-point star on a 17x17 grid (row runs of filled cells).
  const STAR =
    'M8 0h1v17h-1zM0 8h17v1h-17zM2 2h1v1h-1zM14 2h1v1h-1zM3 3h1v1h-1zM13 3h1v1h-1zM4 4h2v1h-2zM7 4h3v1h-3zM11 4h2v1h-2zM4 5h9v1h-9zM5 6h7v1h-7zM4 7h9v1h-9zM4 9h9v1h-9zM5 10h7v1h-7zM4 11h9v1h-9zM4 12h2v1h-2zM7 12h3v1h-3zM11 12h2v1h-2zM3 13h1v1h-1zM13 13h1v1h-1zM2 14h1v1h-1zM14 14h1v1h-1z';

  // 4x4 Bayer thresholds, the same ordered dither as DitherField.
  const BAYER = [
    [0, 8, 2, 10],
    [12, 4, 14, 6],
    [3, 11, 1, 9],
    [15, 7, 13, 5],
  ].map((row) => row.map((v) => (v + 0.5) / 16));

  function cells(points: [number, number][]): string {
    return points.map(([x, y]) => `M${x} ${y}h1v1h-1z`).join('');
  }

  // A dithered glow around the star, fading out by `radius` cells.
  const glow = (() => {
    const cx = STAR_X + 8.5;
    const cy = STAR_Y + 8.5;
    const radius = 16;
    const out: [number, number][] = [];
    for (let y = 0; y < H; y++) {
      for (let x = 0; x < W; x++) {
        const t = Math.min(1, Math.hypot(x + 0.5 - cx, y + 0.5 - cy) / radius);
        const f = (1 - t * t * (3 - 2 * t)) * 0.9;
        if (f > (BAYER[y & 3]?.[x & 3] ?? 1)) out.push([x, y]);
      }
    }
    return cells(out);
  })();

  const sparkles = cells([
    [4, 4],
    [26, 3],
    [34, 7],
    [3, 19],
    [37, 17],
    [7, 34],
    [35, 31],
    [15, 39],
    [30, 39],
  ]);
</script>

<figure class="m-0 w-full max-w-[260px] justify-self-center md:max-w-[400px]" aria-hidden="true">
  <div class="bg-[#c9cbd6] p-[7px] shadow-[0_0_0_3px_#262a3a]">
    <div
      class="border-[3px] border-b-0 border-[#262a3a] px-2 pt-3 pb-4 text-center font-pixel text-[30px] leading-none text-[#262a3a]"
      dir="ltr"
    >
      INTERNET<br />FREEDOM
    </div>
    <svg
      class="block w-full border-[3px] border-[#262a3a] bg-[#262a3a]"
      viewBox="0 0 {W} {H}"
      shape-rendering="crispEdges"
    >
      <path d={glow} fill="#5aba6a" fill-opacity="0.22" />
      <path d={sparkles} fill="#c9cbd6" fill-opacity="0.75" />
      <path d={STAR} transform="translate({STAR_X} {STAR_Y})" fill="#5aba6a" />
    </svg>
  </div>
</figure>
