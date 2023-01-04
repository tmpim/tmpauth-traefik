# gjson

This is https://github.com/tidwall/gjson without "unsafe" (it actually still uses `unsafe`
but it's compatible with yaegi's default settings where `unsafe` is supposedly disabled, when
in-fact it's enabled for stdlib calls so I abuse `reflect` to use `unsafe`).
