# Overstrike — HTB Cyber Apocalypse 2026 (mobile)

**Flag:** `HTB{0v3rstr1k3_r3cut_th3_w0rld_s34l_by_f0rg1ng_th3_mark}`

> *"To reach the truth the forgers have filed as fact, Elric must do the very thing that
> condemns them, and cross on a seal of his own making, one the world itself cannot tell
> from genuine."*

The story tells you the whole solution: you don't collect the true seal, you **re-cut** it.

## 1. Recon: what kind of APK is this?

The handout is a single 200 MB `Overstrike.apk`.

```bash
unzip -l Overstrike.apk | grep -E 'lib/|assets/' | head
#  71366968  lib/arm64-v8a/libgodot_android.so
#   3103832  lib/arm64-v8a/libmonosgen-2.0.so
#     61952  assets/.godot/mono/publish/arm64/Overstrike.dll
```

A **Godot 4 game with the C# (Mono) runtime**. That means `classes.dex` is just the Godot
Android boilerplate — all the game logic lives in the managed assembly
`assets/.godot/mono/publish/arm64/Overstrike.dll` (62 KB).

Note that the C# sources are shipped but truncated to 1 byte each, so they are only there
to tell you the class names:

```bash
unzip -l Overstrike.apk | grep 'assets/scripts'
#  1  assets/scripts/Archive.cs
#  1  assets/scripts/BridgeBuilder.cs
#  1  assets/scripts/GameState.cs
#  ...
```

Extract the assembly:

```bash
unzip -j Overstrike.apk 'assets/.godot/mono/publish/arm64/Overstrike.dll' -d dll/
```

## 2. Reading the assembly

With ILSpy/dnSpy you get C# directly. Without a .NET toolchain, `dnfile` + `dncil`
(both pure Python) are enough to dump the IL and the metadata:

```bash
pip install dnfile dncil
```

A first pass over the string/name heaps already frames the challenge:

```
CarriedMark   WorldSeal   TrueSeal   SealedRecord
Mix           UnsealRegistry         WorldIsAligned
TileHash      Aligned    SHA256
"Carried Mark : 0x"      "World Seal   : 0x"
"The vow-stones are dark. Your mark is not the true seal."
"The vow-stones answer. Cross the rift."
```

### `GameState`

Three interesting members (IL, translated back to C#):

```csharp
// _Process
public override void _Process(double delta) => WorldSeal = Mix(CarriedMark);

// get_WorldIsAligned
public bool WorldIsAligned => WorldSeal == 0xD9A1BB0CABB52586;   // ldc.i8 -2764723033133996666

// Mix
static ulong Mix(ulong x) {
    x += 0x9E3779B97F4A7C15;
    x ^= x >> 30;  x *= 0xBF58476D1CE4E5B9;
    x ^= x >> 27;  x *= 0x94D049BB133111EB;
    x ^= x >> 31;
    return x;
}
```

`Mix` is textbook **splitmix64** (golden-gamma increment + the standard finalizer).

### `BridgeBuilder`

```csharp
public void Rebuild(ulong seal) {
    _lastSeal = seal;
    bool aligned = (seal == 0xD9A1BB0CABB52586);   // same constant
    ...  // aligned -> solid tiles across the rift; otherwise scattered junk from TileHash(seal, i)
}
```

`TileHash(seal, i) = Mix(seal ^ (0xD1B54A32D192ED03 * (i + 1)))` only drives the cosmetic
wobble of the unaligned tiles — the gate is the plain equality.

### `Archive` (the sealed vault at the far side of the rift)

```csharp
void OnBodyEntered(Node3D body) {
    if (body is not Player || !GameState.Instance.WorldIsAligned) return;
    _shown = true;
    // ...
}
public override void _Process(double delta) {
    if (_shown && GameState.Instance.WorldIsAligned)
        Registry.Text = GameState.Instance.UnsealRegistry();
}
```

### `GameState.UnsealRegistry` — the actual crypto

```csharp
public string UnsealRegistry() {
    byte[] key;
    using (var sha = SHA256.Create())
        key = sha.ComputeHash(BitConverter.GetBytes(CarriedMark));   // ulong, LE

    byte[] outBuf = new byte[SealedRecord.Length];
    using (var sha = SHA256.Create()) {
        int o = 0;
        for (int ctr = 0; o < SealedRecord.Length; ctr++) {
            byte[] buf = new byte[key.Length + 4];
            Buffer.BlockCopy(key, 0, buf, 0, key.Length);
            Buffer.BlockCopy(BitConverter.GetBytes(ctr), 0, buf, key.Length, 4);
            byte[] ks = sha.ComputeHash(buf);
            for (int j = 0; j < ks.Length && o < SealedRecord.Length; j++, o++)
                outBuf[o] = (byte)(SealedRecord[o] ^ ks[j]);
        }
    }
    // bytes -> string, non-printables replaced with '▯'
}
```

So it is a **SHA-256 counter-mode keystream keyed on `CarriedMark`**, XORed over an
embedded 56-byte blob. Crucially the key is derived from `CarriedMark`, *not* from
`WorldSeal` — so recovering the mark is the whole game.

## 3. Why you cannot play your way to it

`MarkPickup.OnBodyEntered` just accumulates:

```csharp
GameState.Instance.CarriedMark += Worth;
```

and `Main.BuildMarks()` spawns exactly five pickups whose `Worth` values come from a
static `ulong[5]` in `<PrivateImplementationDetails>`:

```
01 00 .. 02 00 .. 03 00 .. 05 00 .. 07 00 ..   ->  {1, 2, 3, 5, 7}
```

Maximum reachable `CarriedMark` is 18. The vow-stones demand a mark whose splitmix64
image equals `0xD9A1BB0CABB52586`. No in-game route exists — exactly as the briefing says:
*"the old vow-stones will not bridge the fire-rift for any mark he carries."*

## 4. Forging the seal

splitmix64's finalizer is a **bijection**, so it inverts cleanly:

* `x *= C` → multiply by the modular inverse of `C` mod 2⁶⁴ (both constants are odd).
* `x ^= x >> s` → fixed-point iterate `x = y ^ (x >> s)` a few times (converges in ⌈64/s⌉ steps).
* undo the `+ 0x9E3779B97F4A7C15`.

```python
def unmix(y):
    x = _unxorshift(y, 31)
    x = (x * pow(0x94D049BB133111EB, -1, 1 << 64)) & M
    x = _unxorshift(x, 27)
    x = (x * pow(0xBF58476D1CE4E5B9, -1, 1 << 64)) & M
    x = _unxorshift(x, 30)
    return (x - 0x9E3779B97F4A7C15) & M
```

```
unmix(0xD9A1BB0CABB52586) = 0xD7CAAD24DD98B676
```

That is the re-cut mark: the world's own `Mix` cannot tell it from genuine, because it *is*
the preimage.

## 5. Extracting the ciphertext and decrypting

`SealedRecord` is a 56-byte static array; its bytes live in the `FieldRVA` table under
`<PrivateImplementationDetails>` (the field names are the SHA-256 of the data, a Roslyn
convention):

```python
import dnfile
pe = dnfile.dnPE("dll/Overstrike.dll")
for r in pe.net.mdtables.FieldRva.rows:
    print(r.Field.row.Name, pe.get_data(r.Rva, 64).hex())
# 7153... -> 01..02..03..05..07..  (the ulong[5] mark worths)
# F255... -> 0d563344126e440f...   (the 56-byte SealedRecord)
```

Then replay the keystream offline:

```python
key = sha256(struct.pack("<Q", 0xD7CAAD24DD98B676)).digest()
ks  = b"".join(sha256(key + struct.pack("<i", i)).digest() for i in range(2))
flag = bytes(a ^ b for a, b in zip(SEALED_RECORD, ks))
```

```
$ python3 solve.py
World seal (target) : 0xD9A1BB0CABB52586
Forged CarriedMark  : 0xD7CAAD24DD98B676  (15549431037298259574)
Flag                : HTB{0v3rstr1k3_r3cut_th3_w0rld_s34l_by_f0rg1ng_th3_mark}
```

No emulator, no device, no patched APK: everything the vault checks is inside the assembly.

## Takeaways

* Godot + C# APKs are just .NET assemblies in `assets/.godot/mono/publish/<abi>/` — always
  look there before touching `classes.dex` or the 70 MB `libgodot_android.so`.
* When a game gates content on `hash(state) == constant`, check whether the hash is a
  *permutation*. splitmix64, xorshift finalizers and multiply-xorshift mixers are all
  invertible — a "one-way looking" check can be a straight preimage.
* Roslyn stores array initializers in `FieldRVA` under `<PrivateImplementationDetails>`,
  with the field name being the SHA-256 of the blob. That's where embedded ciphertexts hide.
