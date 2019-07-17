GHIDRA RL78
===========

WIP RL78 implementation for Ghidra SRE. This repo should now be at the point of being at least somewhat usable for reversing RL78. Pull requests and issue submissions would be appreciated.

![Screenshot of current disassembly](https://raw.githubusercontent.com/hedgeberg/RL78_sleigh/master/images/rl78_state.png)


Setup
-----

Follow the setup instructions as explained in [Ghidra_Falcon](https://github.com/Thog/ghidra_falcon), and if you plan to modify any of the files I recommend you go into $(ghidra_root)/Ghidra/Extensions/rl78_sleigh/data and delete the "languages" folder, then symlink to the data/languages folder of whereever you download this repo to. That will allow you to iterate and test in Ghidra without having to go through a loop of uninstall->restart->reinstall->restart->reopen project every time you want to test changes.


Status
------

What works:
+	Disassembles all code in the test binary, to some degree of accuracy. Has known bugs, but it mostly functions. Sample project is included in the ghidra_work folder.
+ 	Decompiler handles basic flow correctly (but still has a looooooong way to go, switch idioms in particular are messy)
+ 	A lot of auto-discovered memory offsets are good as-is, but some leave a lot to be desired.  

What doesn't work yet:
+ 	Large body of instructions still unimplemented, but none of the most common ones.
+	Decompiler output is full of nastiness, as no work has been done on refining this
+ 	Stack and RAM had to be separated, as Ghidra gets confused by the fact that the stack pointer doesn't actually line up with the area being referenced. This may be a more fundamental ghidra issue that needs some modifications to the codebase before a cleaner, more unified memory map can be designed.

What's on the docket:
+ 	Adding context register functionality to enable register banking.
+ 	Implementing the remainder of the ISA
+ 	Huge amount of cleanup work in the .slaspec file, it's super messy
+	Experimenting with a basic loader
+ 	Default memory mappings and register locations


FYI
---

For those interested in extending this (or just learning about RL78), I've included the Renesas ISA programmer's manual in the "docs" folder.


Credits
-------

Thanks to [hthh](https://github.com/hthh/), [thog](https://github.com/thog), and [roblabla](https://github.com/roblabla) for their work on [Ghidra_Falcon](https://github.com/Thog/ghidra_falcon), which served as the base workflow for this project (i.e. I stole their repo and build system and just edited a couple files with the exception of the rl78 defintion files). Definitely check through their repo, their debugging workflow that they highlighted there is how I've been debugging this. 
