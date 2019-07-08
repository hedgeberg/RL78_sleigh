GHIDRA RL78
===========

WIP RL78 implementation for Ghidra SRE. 

Placeholder for image


Setup
-----

Follow the setup instructions as explained in [Ghidra_Falcon](https://github.com/Thog/ghidra_falcon), and if you plan to modify any of the files I recommend you go into $(ghidra_root)/Ghidra/Extensions/rl78_sleigh/data and delete the "languages" folder, then symlink to this languages folder of whereever you download this repo to. That will allow you to iterate and test in Ghidra without having to go through a loop ofuninstall, restart, reinstall, restart, and reopen the project every time you want to test changes.


Status
------

What works rn: 
+	not much
+	A few instructions, basically. Just enough to get the screenshot above.


What doesn't work yet:
+ 	most instructions
+	decompiler
+ 	different versions of ISA


FYI
---

For those interested in extending this (or just learning about RL78), I've included the Renesas ISA programmer's manual in the "docs" folder.


Credits
-------

Thanks to [hthh](https://github.com/hthh/), [thog](https://github.com/thog), and [roblabla](https://github.com/roblabla) for their work on [Ghidra_Falcon](https://github.com/Thog/ghidra_falcon), which served as the base workflow for this project (i.e. I stole their repo and build system and just edited a couple files with the exception of the rl78 defintion files). Definitely check through their repo, their debugging workflow that they highlighted there is how I've been debugging this. 
