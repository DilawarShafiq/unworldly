# Unworldly Demo — VHS tape file
# Record with: vhs demo/demo.tape
# Outputs: assets/demo.gif
# Requires: https://github.com/charmbracelet/vhs

Output assets/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 920
Set Height 600
Set Framerate 15
Set FontFamily "JetBrains Mono"
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 0ms

# Run the simulation
Type "python demo/simulate.py"
Enter
Sleep 35s
