---
title: "File Management In Linux"
last_modified_at: 2020-10-02T14:40:02-05:00
categories:
  - Linux
author_profile: false
tags:
  - Linux
  - File Management
  - Archiving
  - Compression
---


# Copy
---------------------------------------------
Copy files and directories from source to destination

Syntax for copying files is quite simple

## Files
```console
cp  <source> <destination>
    - source and destination can be relative as well as absolute path
```
eg : `cp /etc/passwd /home/red/ro`
>Here  /etc/passwd is copied to /home/red and stored as filename ro.If destination filename is not specified, then the filename will be preserved.

## Directories
For directories we need to add -r flag 
```console
cp -r <source> <destination>
```

eg : `cp -r /home/red/dir1 /home/red/dir2/new_dir`
>Here , directory dir1 is copied to dirq2 with folder name new_dir. If destination directory is not specified, then the directory name will be preserved.\

-i for interactive mode. 
>If same filename is found in the destination directory, shell prompts before overwriting the existing files.

There are many flags for this command for setting symbolic or hard link, copying only attribute and many more. 
For more information type `man cp` on shell.

---------------------------------------

# Move

---------------------------------------------
Move or rename files

Syntax for moving or renaming files is quite simple

## Files and Directories
```console
mv  <source> <destination>
    - source and destination can be relative as well as absolute path
```
eg : `mv /home/red/tmp /home/red/ro`
>Here  /home/red/tmp is moved to /home/red/ and stored as filename ro.If destination filename is not specified, then the filename will be preserved. Unlike copy move does not need -r flag for directories. For **renaming** we can move the file in the same location with a different name `mv ro roshan` renames file ro to roshan.

-i for interactive mode. 
>If same filename is found in the destination directory, shell prompts before overwriting the existing file. We can use -n if we do not want the destination file to be overridden.

For more information type `man vp` on shell.

-----------------------------------------------------