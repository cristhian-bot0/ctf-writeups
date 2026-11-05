# SaltCrown — Write-up (mobile)

> Alyss has threaded the dead of Crownspire to the city bell. It strikes, they step, all
> together. You play Elric Ashspar, an engineer with no weapon and no way to fight them.
> The bell's strike-plate is a counterfeit, and counterfeits fail under repetition. Break
> the march, force the bell to work, and read the failure.

**Flag:** `HTB{p3rf3ct_f4c3_wr0ng_sp1n3}`

## TL;DR

An Android game (Godot 4 + Mono/C#) mints the flag only when the bell's counterfeit
strike-plate **fractures under repeated strikes**. The fracture "seed" is a hash fold over
the five shards you have wedged into the march's choke points, and unsealing that seed
yields the flag. The whole thing — including the native `AshVault` GDExtension that
computes a per-choke "phase bucket" — is deterministic, so we recover the seed offline and
never touch an emulator.

## 1. Triage

The handout is a ~200 MB APK. `unzip -l` shows the classic Godot-4-with-Mono layout:
`libgodot_android.so`, `libmonosgen-2.0.*`, and a managed publish tree under
`assets/.godot/mono/publish/`. Everything game-specific is one small assembly:

```
assets/.godot/mono/publish/arm64/SaltCrown.dll   (109 KB)
```

There is also a game-specific native GDExtension:

```
lib/<abi>/libashvault.android.template_release.<abi>.so
assets/native/ashvault.gdextension        # entry_symbol = saltcrown_library_init
assets/rubbings/ashvault.dat              # 256 bytes
```

## 2. Disassembling the managed logic

No `dotnet`/`ilspycmd` on the box, so we dump IL with **dnfile + dncil** (a ~120-line
`ildump.py`). The interesting namespace is `SaltCrown.Mechanism`, plus `SaltCrown.Director`.

The flag is produced by `Director.Forge()`, which runs from `OnFractured`:

```csharp
void OnStruck(force) {
    _plate.Endure(force, SeatsBiting);          // fatigue += force^2 * (1 + 0.85*biting)
    // ... if the march overruns HoldLine -> Lose()
}
void OnFractured() { State = 1; Forge(); ... }  // fires when Fatigue >= FractureThreshold

void Forge() {
    uint state = 0x811C9DC5;                     // FNV-1a offset basis
    foreach (var seat in _seats.Where(s => s.Bites)
                               .OrderBy(s => s.ChokeIndex))
        state = SaltCrownSpec.Measure(state, seat.ChokeIndex,
                                      Tolerances.PhaseBucket(seat.ChokeIndex));
    Crown = SaltCrownSpec.Unseal(state);         // the flag
}
```

The primitives:

```csharp
uint Mix(uint a, uint b) {                        // FNV prime + xxhash-ish avalanche
    a ^= b; a *= 0x01000193; a ^= a >> 15;
    a *= 0x85EBCA77; a ^= a >> 13; return a;
}
uint Measure(uint s, uint a, uint b) => Mix(Mix(s, a), b);

string Unseal(uint seed) {
    var outb = new byte[SealedSpec.Length];       // 24 bytes
    uint st = seed;
    for (int i = 0; i < outb.Length; i++) {
        st = Mix(st, (uint)i);
        outb[i] = (byte)(SealedSpec[i] ^ (byte)(st >> 24));
    }
    return "HTB{" + Encoding.ASCII.GetString(outb) + "}";
}
```

`SealedSpec` is a 24-byte static array (its field name is literally the SHA-256 of the
blob): `75c9ab6b9a53cfbf1fe97e4a939425e029cf87a9c280dedc`.

**Key observation:** the seed depends *only on the set of `ChokeIndex` values of the shards
that bite* (sorted). The beat/`BeddedPhase` gates whether a shard *bites*, but does not feed
the fold — `PhaseBucket` takes the integer `ChokeIndex`, not the phase.

## 3. Which choke buckets?

`Tolerances.SeatsAtChoke` scans bucket `i = 0..7` with `ChokeZ(i) = 14 - 6*i`, and only
accepts `i` where the corridor is a *choke*:

```
HalfWidthAt(z) = Lerp(9.5, 5.2, clamp(InverseLerp(14, -40, z), 0, 1))
choke  <=>  HalfWidthAt(z) <= 8.1  <=>  z <= -3.58  <=>  i >= 3
```

So the valid chokes are exactly `i ∈ {3,4,5,6,7}` — the five shards the HUD counts as
`.../5`. A winning run wedges one biting shard into each, so `Forge` folds over
`ChokeIndex = [3, 4, 5, 6, 7]`.

## 4. The native `PhaseBucket`

`Tolerances.PhaseBucket(c)` → `WearLattice.AdmitBucket(c)` →
`ClassDB.Instantiate("AshVault").Call("admit_bucket", rubbing, c)` in `libashvault`.

The `admit_bucket` string has a single xref (the class registration); the bound method is
at file offset `0x1dc30` in the x86_64 `.so`. Reversed, it is a pure function of the
256-byte rubbing and the bucket:

1. **Build** a 64-entry `uint32` table `T`: for each `salt = 0..63`, hash all 256 rubbing
   bytes with an FNV-style mixer (each byte offset by `salt`).
2. **Diffuse** `T` for **4096 rounds**; each round is an xxhash-like neighbour mix
   (`rol 7/27/13`, `*0x85EBCA77`, `*0xC2B2AE3D`, round constant `k*0x9E3779B9`).
3. **Combine** with the bucket (independent of the table build):

   ```
   ia = (7*bucket + 3)  & 63
   ib = (23*bucket + 41) & 63
   v  = rol(T[ib], 11) ^ T[ia]
   return ((v >> 5) ^ (v >> 13)) & 0xFF
   ```

The table build is independent of the bucket, so compute it once and read off the byte for
each choke. Reimplemented in `solve.py`.

## 5. Recovering the flag

```
choke=3  phaseBucket=178  state=0x28ec5230
choke=4  phaseBucket=26   state=0x20ef93a6
choke=5  phaseBucket=6    state=0x342108d7
choke=6  phaseBucket=101  state=0x9fc192c3
choke=7  phaseBucket=234  state=0x75f944d2

Fracture seed : 0x75f944d2
Flag          : HTB{p3rf3ct_f4c3_wr0ng_sp1n3}
```

The 24 unsealed bytes are clean, meaningful ASCII — and they echo the Director's own line
when a shard seats without biting: *"It seats clean and does nothing. Perfect face — wrong
spine. Wrong beat."* That semantic match is the proof the native port is correct.

```
$ python3 solve.py
```

## Takeaways

- Godot + Mono mobile challenges hide all logic in one tiny `SaltCrown.dll`; dump IL with
  dnfile/dncil and read it directly.
- The "impossible in-game" trick (à la Overstrike/Proofmark): the flag is a hash of a game
  state you are meant to *reach* by playing, but which you can just *compute* — here the
  fracture seed over the five choke buckets.
- A native GDExtension is not a wall: `admit_bucket` is a single self-contained function;
  reverse it from the `.so` and reimplement it rather than emulating Android.
