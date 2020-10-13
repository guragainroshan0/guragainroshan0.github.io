---
title: "Tmux : TryHackMe"
last_modified_at: 2020-10-13T14:40:02-05:00
categories:
  - TryHackMe
author_profile: false
tags:
  - tmux
  - linux 
  - TryHackMe
---
tmux is a terminal multiplexer. It lets you switch easily between several programs in one terminal, detach them (they keep running in the background) and reattach them to a different terminal.

# 1. Cheatsheet

![/assets/images/TryHackMe/Tmux/Untitled.png](/assets/images/TryHackMe/Tmux/Untitled.png)

## Initial Sequence to send commands

```bash
ctrl + b
```

# Creating a new session

## For session without a custom name

```bash
$ tmux
```

### Session with custom name

```bash
$ tmux new -t <session_name>
```

## Detach from the current session

```bash
ctrl + b + d
```

## List all sessions #not_in_cheatsheet

```bash
$ tmux ls
```

## Attach a tmux session

### By name

```bash
$ tmux a -t <session_name>
```

## Creating a new window in a session

```bash
ctrl + b + c 
```

## Enter copy mode

Used when copying of results is needed. Used when screen is full and needs to scroll above. Similar to less 

```bash
ctrl + b + [
```

### Start Selection

In order to start the selection of contents press 

```bash
ctrl + space
```

and use arrow keys to go to the end of text you want to copy.

### Copy Selection

```bash
ctrl + w or alt + w
```

### Paste Selection

```bash
ctrl + b + ]
```

### Go to top

```bash
alt + shift + ,
```

### Exit copy mode

```bash
q
```

## Window operations

Panes are sections of windows that has been split into different screens.

### Split Vertically

```bash
ctrl + b + %
```

### Split Horizontally

```bash
ctrl + b + "
```

### Moving between panes

```bash
ctrl + b + <arrow_keys>
```

### Convert pane to window

### Rename window

```bash
ctrl + b + ,
```

### List windows

```bash
ctrl + b + w
```

### Kill window

```bash
ctrl + b + &
```

### Search window

```bash
ctrl + b + f
```

### Killing pane

If a pane becomes unresponsive

```bash
ctrl +b + x
```

### Close a window

```bash
$ exit
```

Default first session name is 0 when not specified.

![/assets/images/TryHackMe/Tmux/Untitled%201.png](/assets/images/TryHackMe/Tmux/Untitled%201.png)

```bash
ctrl + b + !
```