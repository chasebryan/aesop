# The Workbench — AESOP's Graphical Environment
> Every command as a form, results you can click back into the input, and live charts of what you are looking at.

## The fable

In *The Crow and the Pitcher*, the crow cannot reach the water, so it drops in
pebbles one at a time until the level rises. Most real ciphertext is solved the
same way: identify, decode a layer, look again, break the next. The workbench
keeps the pitcher in front of you — one input, one output, and every tool a
click away — so each pebble lands where you can see it.

## Starting it

```console
$ aesop gui                      # reopen where you left off
$ aesop gui vigenere             # open on a particular command
$ aesop gui --theme light        # dark is the default
```

The workbench is built on Tkinter from Python's standard library, so it needs
no extra packages. If Python reports that Tkinter is missing, install your
platform's Tk bindings (`python3-tk` on Debian and Ubuntu, `python3-tkinter` on
Fedora). `aesop version` shows whether it is available.

## The window

| area | what it is for |
|------|----------------|
| **Commands** (left) | The whole catalogue, grouped as in `aesop list`. Type in the search box to filter by name, alias or description. |
| **Workbench** tab | The selected command: input, options, examples, and the output below. |
| **Inspector** (right) | Live statistics and charts for whatever is in the input box. |
| **Field guide** tab | This manual, searchable. Commands and `aesop manual …` references are clickable. |
| **History** tab | Every run this session. Double-click one to bring back its form and output. |

## Working in it

1. **Put data in the input box** — type, paste, or choose a file. The input is
   a shared workspace: it stays put when you switch commands.
2. **Pick a command and set options.** The form is generated from the same
   definitions as the command line, and the exact equivalent command is shown
   above the *Run* button, ready to copy into a terminal or a write-up.
3. **Run.** Long solvers run in a separate process, so the window stays
   responsive and *Stop* really stops them.
4. **Chain.** Send a result back to the input with *Use as input* — under a
   result, from the right-click menu on any table cell, or with `Ctrl+U` — then
   run the next command on it.

Unsure where to begin? Put the data in and run `auto`, or read the inspector's
*Looks like* list and follow one of its suggestions.

### The inspector

| reading | what it tells you |
|---------|-------------------|
| **Entropy** | Near 8 bits per byte means encrypted or compressed; around 4 is text. See `aesop manual entropy`. |
| **Index of coincidence** | About 0.066 is English-like (plaintext or a monoalphabetic cipher); about 0.038 is flat (long key or random). See `aesop manual frequency`. |
| **Letter frequency** | Observed letters as bars against the English profile as marks. A shifted copy of the English shape suggests Caesar; a flattened one suggests Vigenère. |
| **Byte values** | Shown instead of letters when the data is not text. |
| **Entropy along the data** | Where in a file the random-looking regions are. |

Like `identify`, `freq` and `entropy`, the inspector analyses the input *as
given*. Choose an explicit *Decode as* to analyse the decoded bytes instead.

### The command bar

The prompt under the output accepts any AESOP command line, exactly as you
would type it in a terminal (the leading `aesop` is optional). Use the up and
down arrows to recall earlier lines.

```console
vigenere -k LEMON --encode 'Attack at dawn'
caesar -h
manual xor
```

## Keys

| key | action |
|-----|--------|
| `Ctrl+Enter` | Run the current command. |
| `Esc` | Stop the running command. |
| `Ctrl+K` | Find a command. |
| `Ctrl+U` | Use the result as the next input. |
| `Ctrl+O` | Open an input file. |
| `Ctrl+S` | Save the output as text. |
| `Ctrl+L` | Clear the output. |
| `F1` | Open the field guide for the current command. |
| `Ctrl+Q` | Quit. |

## Good to know

- **Files win over text.** When a file is chosen the text box is ignored, as
  on the command line. Sending a result to the input clears the file.
- **Nothing leaves your machine.** The workbench opens no network ports; it
  talks to its worker process over a private pipe.
- **Settings** (theme, window size, last command) are kept in
  `~/.config/aesop/gui.json`.
- **New commands appear automatically.** The workbench reads the command
  registry, so a technique you add gets a form without any GUI code.

## See also

- `aesop manual getting-started` — the five-minute tour.
- `aesop manual auto` — the one-command solver.
- `aesop manual identify` — how AESOP guesses what a blob is.
