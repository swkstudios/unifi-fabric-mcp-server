# Records the raw demo into scripts/demo/out/. From the repository root:
#   vhs scripts/demo/demo.tape && uv run --with pillow --with numpy python scripts/demo/compose.py
# compose.py adds the camera-image panel and trims the tail; it writes docs/assets/demo.{mp4,gif}.
# Needs vhs (https://github.com/charmbracelet/vhs), uv, ffmpeg and the JetBrains Mono font.
# Synthetic data only: run.sh starts the local mock API; nothing reaches a real controller.
Output scripts/demo/out/raw.gif
Output scripts/demo/out/raw.mp4

Set Shell "bash"
Set FontFamily "JetBrains Mono"
Set FontSize 19
Set Width 1300
Set Height 960
Set Padding 22
Set Margin 34
Set MarginFill "scripts/demo/background.png"
Set WindowBar Colorful
Set WindowBarSize 36
Set BorderRadius 12
Set Theme "Catppuccin Mocha"
Set Framerate 20
Set TypingSpeed 0
Set CursorBlink false
Env BASH_SILENCE_DEPRECATION_WARNING "1"
Env PS1 "$ "
Env DEMO_SNAPSHOT_OUT "scripts/demo/out/snapshot.jpg"

# Off camera: start the mock and the client. The client draws its first frame
# (the session header and an empty prompt) before the recording is shown.
Hide
Type "mkdir -p scripts/demo/out && clear && ./scripts/demo/run.sh"
Enter
Sleep 2500ms
Show

# The client paces itself (about 60 s); compose.py trims the tail to a 3 s hold.
Sleep 68s
