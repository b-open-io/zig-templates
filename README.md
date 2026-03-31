# zig-templates

Bitcoin script templates for 1Sat Ordinals -- Zig implementation.

Parity with [go-templates](https://github.com/b-open-io/go-templates) and [@1sat/templates](https://github.com/1sat-sdk).

## Templates

- `inscription` -- Ordinal inscription envelope
- `bitcom/map` -- Magic Attribute Protocol (MAP)
- `bitcom/aip` -- Author Identity Protocol (AIP)
- `bitcom/sigma` -- SIGMA signatures (Type-42)
- `bitcom/b` -- B:// data carrier protocol
- `ordlock` -- OrdLock marketplace listings
- `lock` -- Timelock (CLTV)
- `opns` -- OpNS domain registration
- `bsv21` -- BSV21 fungible tokens

## Build

```bash
zig build
zig build test
```

## Dependencies

- [bsvz](https://github.com/b-open-io/bsvz) -- BSV foundation library
