# DefenseEvasion
Bypassing AV, EDR, Application Whitelisting and ASR Rules

### Purpose of this repo
I create the things in this repo bit by bit, mostly as part of my personal learning process on different OPSEC topics in Red Teaming. So don't expect anything spectacular ツ. If you find any of this useful, feel free to use it. Critical feedback and suggestions for improvement are welcome.

### OPSEC-improved Shellcode Runners
The classical method of shellcode injection - the VirtualAllocEx/WriteProcessMemory/CreateRemoteThread pattern - has numerous OPSEC disadvantages and is nowadays often unlikely to be successful against modern defense mechanisms. In this repo some techniques for OPSEC-improved shellcode runners are tried out and combined. Of course, none of these general techniques were discovered by me. I am just recombining and playing around with some of them as part of my personal learning process and to address some specific issues I came across. See [ShellcodeRunners](https://github.com/Pwnd4/DefenseEvasion/tree/main/ShellcodeRunners).

### Mindmap: Cobalt Strike Defense Evasion Overview
I created this mind map to organize my thoughts and keep track of defense-bypassing techniques I've learned from others over time. It is divided into the branches AntiVirus, EDR, Attack Surface Reduction Rules (ASR), Application Whitelisting (Applocker and WDAC) and Network Inspection. Specifically, some things are related to Cobalt Strike, but the basic concepts are universal. A lot of stuff in a small space, the .png below is 8.000 x 8.000 px so you can zoom in. But some find [the PDF version](https://github.com/Pwnd4/DefenseEvasion/raw/main/CobaltStrikeDefenseEvasion.pdf) more comfortable to read.

![CobaltStrikeDefenseEvasion](https://github.com/Pwnd4/DefenseEvasion/blob/main/CobaltStrikeDefenseEvasion.png)
