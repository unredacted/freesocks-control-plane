/**
 * The application releases the Hysteria app checks install
 * (docs/client-compatibility.md § "Hysteria in real apps"). Each is the
 * upstream release asset pinned by the SHA-256 GitHub records for it; bump the
 * version, URL and digest together (`gh api repos/<repo>/releases`).
 */
export const hysteriaApps = {
  v2rayNG: {
    version: '2.3.15',
    url: 'https://github.com/2dust/v2rayNG/releases/download/2.3.15/v2rayNG_2.3.15_x86_64.apk',
    sha256: '6c5276597d913c1330334b99d03b273201834cf475ab6aa709f7413097613bd5',
  },
  v2rayN: {
    version: '7.25.6',
    url: 'https://github.com/2dust/v2rayN/releases/download/7.25.6/v2rayN-linux-64.deb',
    sha256: 'b7220c636d17b925814804d4171cba9b3aa1f771baae8b570403f2c8850406e8',
  },
} as const;
export type HysteriaApp = keyof typeof hysteriaApps;
