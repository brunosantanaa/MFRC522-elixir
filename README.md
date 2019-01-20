# MFRC522-elixir

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `mfrc522` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:mfrc522, git: "https://github.com/brunosantanaa/MFRC522-elixir.git"}
  ]
end
```

## Reader

```elixir
iex> MFRC522.start_link
iex> MFRC522.mode(:reader)
```

Place the RFID TAG next to the RC522 reader.

```elixir
iex> flush()
{:mfrc522, [123, 123, 123, 123, 123]}
```



Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/mfrc522](https://hexdocs.pm/mfrc522).
