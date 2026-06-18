// collector/cdp — detect an active CDP Runtime.enable via the prototype-chain Proxy ownKeys trap.
// Arms a proxy whose ownKeys trap fires when devtools/automation previews it; clean envs stay false.

export interface CdpProbe {
  /** The object to expose where a CDP Runtime.enable preview will enumerate it. */
  readonly marker: object;
  /** Whether the ownKeys trap has fired (i.e. something enumerated the marker). */
  triggered(): boolean;
}

/**
 * Arm a CDP probe. In a normal page nothing enumerates the marker, so `triggered()` stays false;
 * when CDP `Runtime.enable` is active, the console object preview reads the marker's keys and the
 * trap fires. This is the live replacement for the V8 `Error.stack` trick that died in 2024-25.
 */
export function armCdpProbe(): CdpProbe {
  let fired = false;
  const marker = new Proxy(
    {},
    {
      ownKeys(target): ArrayLike<string | symbol> {
        fired = true;
        return Reflect.ownKeys(target);
      },
    },
  );
  return { marker, triggered: () => fired };
}
