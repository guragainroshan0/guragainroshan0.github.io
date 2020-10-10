---
title: "First Docker Container"
last_modified_at: 2020-09-24T14:40:02-05:00
categories:
  - Docker
author_profile: false
tags:
  - Container
  - Docker
---

From the first part of this series, we are clear that why we need containers and how container differ from virtual machines.

# What this post has
* Installing Docker
* Running a container
* What docker image is ?
* Getting image from **[DockerHub](https://hub.docker.com/)**
* Container Isolation
* Executing commands inside a docker container


# Installing Docker
Before getting into much details, let's first install docker 
```console
$ sudo apt update;sudo apt install docker.io -y
```
`sudo apt update` updates the local database to get access to latest versions.\
`sudo apt install docker.io -y` install docker, -y flag accepts the prompt.

Test the installation
```console
$ docker --version
Docker version 19.03.6, build 369ce74a3c
```
So now we have installed docker. Lets run a container

# Running a container

```console
$ sudo docker run hello-world
Unable to find image 'hello-world:latest' locally
latest: Pulling from library/hello-world
0e03bdcc26d7: Pull complete 
Digest: sha256:4cf9c47f86df71d48364001ede3a4fcd85ae80ce02ebad74156906caff5378bc
Status: Downloaded newer image for hello-world:latest

Hello from Docker!
This message shows that your installation appears to be working correctly.

To generate this message, Docker took the following steps:
 1. The Docker client contacted the Docker daemon.
 2. The Docker daemon pulled the "hello-world" image from the Docker Hub.
    (amd64)
 3. The Docker daemon created a new container from that image which runs the
    executable that produces the output you are currently reading.
 4. The Docker daemon streamed that output to the Docker client, which sent it
    to your terminal.

To try something more ambitious, you can run an Ubuntu container with:
 $ docker run -it ubuntu bash

Share images, automate workflows, and more with a free Docker ID:
 https://hub.docker.com/

For more examples and ideas, visit:
 https://docs.docker.com/get-started/
```
 ```docker run <image-name>```\
First the **Docker Engine** looks if the hello-world image is available locally. Here it is unable to find so it searches the image in default docker registry i.e **DockerHub** , pulls the image and runs it in a container . The output we see is the output of the hello-world container. After the output, the container exits. Image showing what happened

![Behind The Scene](/assets/images/docker/starting-docker-container/ops-basics-hello-world.svg)
<p class='caption' markdown='1'>
[Source](https://training.play-with-docker.com/ops-s1-hello/)
</p>

Since it downloaded a docker image, let's see the docker image
```console
$ sudo docker image ls 
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
hello-world         latest              bf756fb1ae65        8 months ago        13.3kB
```

All the image