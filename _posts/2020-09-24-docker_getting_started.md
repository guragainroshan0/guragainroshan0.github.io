---
title: "Getting started with Docker"
last_modified_at: 2020-09-12T14:40:02-05:00
categories:
  - docker
author_profile: false
tags:
  - virtualization
  - Docker
---

Before getting to know what docker is, let's start by why docker is used and why it is so popular.

![/assets/images/docker/getting-started/first-post/Untitled.png](/assets/images/docker/getting-started/first-post/Untitled.png)

Suppose you have a node application that runs in your machine with multiple dependencies and customized settings. You want to share your application with other people as well. The system in which the application is to be run changes as a result, the application might not work on other machines. So we need some form of mechanism for easier packing, shipping, and deployment of the application. This is were containerization shines. 

Containers solve this problem. You may be thinking the same thing could be done using a virtual machine. A developer writes all code in a virtual machine and provides the virtual machine files. Which means we have a new question to answer how the container is different from a virtual machine? 

> Containers and virtual machines have similar resource isolation and allocation benefits but function differently because containers virtualize the operating system instead of hardware.

# Virtual Machine

![/assets/images/docker/getting-started/first-post/Untitled%201.png](/assets/images/docker/getting-started/first-post/Untitled%201.png)

                                    Fig: Virtual Machine \(Source [docker](https://www.docker.com/sites/default/files/d8/2018-11/container-vm-whatcontainer_2.png)\)

**Virtual Machines are an abstraction of physical hardware turning one machine into many machines**. A virtual machine is a virtual environment that functions as a virtual computer system with its own CPU, memory, network interface, and storage on the physical hardware system. Virtualization allows you to run two completely different OSes on the same hardware. 

Software called **hypervisor** separates the machine's resources from the hardware and provisions them appropriately so they can be used by the VM. Each VM includes a full copy of the operating system the application necessary binaries and libraries - taking up tens of GBs also booting is slow in VM compared to containers.

Lets first know about the layers

1. **Infrastructure**

    Infrastructure could be anything that has resources to run an operating system. It could be your personal computer, cloud-hosted instances, or bare metal servers you own. The resources of these infrastructures are utilized by the virtual machines for their operation.

2. **Operating System**

    On top of the infrastructure operating system runs also called a host operating system for the virtual machines.  Virtual machines run on top of this host operating system. It is equipped with a hypervisor.

3. **Hypervisor**

    The host operating system runs software called hypervisor which is responsible for separating the machine's resources from the hardware and provisions them appropriately so they can be used by the VM. It allows multiple VM's to run on a single machine. The hypervisor treats compute resources-like CPU,memory and storage as a pool of resources that can be easily relocated between existing VMs or new VMs.There are two types of hypervisors. 

    - Type 1

        A type 1 hypervisor is on bare metal. In this, the hypervisor directly communicates with the system hardware than relying on the host operating system. VM resources are scheduled directly to the hardware by the hypervisor. eg KVM

    - Type 2

        A type 2 hypervisor is hosted. VM resources are scheduled against a host operating system, which is then executed against the hardware. eg VMware and VirtualBox

    The above figure shows the use of KVM as hypervisor.

4. **Guest Operating System**

    This is the operating system that runs on the virtual machine. This OS needs resources for storage, CPU operations and these resources are utilized form the pool of resources with the help of a hypervisor. All the applications that are needed to run a program can be installed in this guest operating system. So if a developer writes a program on a virtual machine, that can be directly deployed with the help of a virtual machine.

We can see few properties here

- Each virtual machine is isolated from each other even though they share the same resources. This provides security.
- High resources are needed for the operation of a VM.
- Since an operating system needs to be booted, boot time is also high
- Hardware virtualization is done.

# **Containerized Applications**

Docker is a tool designed to make it easier to create, deploy, and run applications by using containers. Since Docker uses containers, lets first understand how it works

![/assets/images/docker/getting-started/first-post/Untitled%202.png](/assets/images/docker/getting-started/first-post/Untitled%202.png)

**Containers are abstractions at the application layer that packages code and dependencies together. Containers provide operating-system-level virtualization by abstracting the "user space".**

Containers look like VM as they have private space for processing , network interface and Ip address, can mount file system. One big difference between VMs and container is that containers share the host's system's kernel with other containers. Each container gets its own isolated user space to allow multiple containers to run on single host machine. From the image we can see that the OS level architecture is being shared across containers. The only parts that are created from scratch are the binaries that are needed. This is what makes containers so light weight.

Lets first understand the above image, 

Infrastructure and host operating system are same as in case of virtual machine.

1. Docker

    Docker engine is installed on top of the host operating system which manages and runs the container. `App A`, `App B` are docker containers that are managed by the docker engine.

Docker uses Linux Kernel features like namespaces and control groups to create containers on top of an operating system. 

How these namespaces work is, all the global resources are wrapped into namespaces so that they are visible only to those processes that run in the same namespace. Let's assume a namespace X is given to a chunk of the disk then the process in the same namespace i.e X can only access the disk but another process cannot see or access it. Each container runs on its own namespace but uses exactly the same kernel as all other containers. The isolation happens because the kernel knows the namespace that was assigned to the process and during API calls it makes sure that the process can only access resources in its own namespace. 

Control groups limit an application to a specific set of resources. It allows the Docker engine to share available hardware resources to containers and optionally enforce limits and constraints. For example, limiting the available memory to a specific container.

Few properties we can see

- Since it uses the host OS, the size of containers are very small compared to VM.
- Since OS is not booted, startup time is very low compared to VM
- Performs OS vitulization
- Process level isolation is performed, so it is less secure than VM
- Requires less memory

So when to use VM and when to use containers

- VMs are a better choice for running apps that require all of the operating system’s resources and functionality when you need to run multiple applications on servers, or have a wide variety of operating systems to manage.
- Containers are a better choice when your biggest priority is maximizing the number of applications running on a minimal number of servers.

Lets view a bit more about Docker Engine 

# Docker Engine

Docker Engine is a client-server application with these major components:

- A server which is a type of long-running program called a daemon process (the `dockerd` command).
- A REST API which specifies interfaces that programs can use to talk to the daemon and instruct it what to do.
- A command line interface (CLI) client (the `docker` command).

![/assets/images/docker/getting-started/first-post/Untitled%203.png](/assets/images/docker/getting-started/first-post/Untitled%203.png)

                                            Fig: Docker engine architecture  \([source](https://docs.docker.com/engine/images/engine-components-flow.png)\)

The CLI uses the Docker REST API to control or interact with the Docker daemon through scripting or direct CLI commands. Many other Docker applications use the underlying API and CLI.

The daemon creates and manages Docker *objects*, such as images, containers, networks, and volumes.

# Docker Architecture

Docker uses a client-server architecture. The Docker client talks to the Docker daemon, which does the heavy lifting of building, running, and distributing your Docker containers. The Docker client and daemon can run on the same system, or you can connect a Docker client to a remote Docker daemon. The Docker client and daemon communicate using a REST API, over UNIX sockets or a network interface.

![/assets/images/docker/getting-started/first-post/Untitled%204.png](/assets/images/docker/getting-started/first-post/Untitled%204.png)

### **The Docker daemon**

The Docker daemon (`dockerd`) listens for Docker API requests and manages Docker objects such as images, containers, networks, and volumes. A daemon can also communicate with other daemons to manage Docker services.

### **The Docker client**

The Docker client (`docker`) is the primary way that many Docker users interact with Docker. When you use commands such as `docker run`, the client sends these commands to `dockerd`, which carries them out. The `docker` command uses the Docker API. The Docker client can communicate with more than one daemon.

### **Docker registries**

A Docker *registry* stores Docker images. **Docker Hub** is a public registry that anyone can use, and Docker is configured to look for images on Docker Hub by default. You can even run your own private registry.

When you use the `docker pull` or `docker run` commands, the required images are pulled from your configured registry. When you use the `docker push` command, your image is pushed to your configured registry.

### **Docker objects**

When you use Docker, you are creating and using images, containers, networks, volumes, plugins, and other objects. This section is a brief overview of some of those objects.

### **IMAGES**

An *image* is a read-only template with instructions for creating a Docker container. Often, an image is *based on* another image, with some additional customization. For example, you may build an image that is based on the `ubuntu` image but installs the Apache web server and your application, as well as the configuration details needed to make your application run.

### **CONTAINERS**

A container is a runnable instance of an image. You can create, start, stop, move, or delete a container using the Docker API or CLI. You can connect a container to one or more networks, attach storage to it, or even create a new image based on its current state.

After the basic concepts of docker, VMs vs containers. In the next post, we will be learning how to work with docker.

Reference : 

[https://www.docker.com/resources/what-container#/package_software](https://www.docker.com/resources/what-container#/package_software)

[https://www.redhat.com/en/topics/virtualization/what-is-a-virtual-machine](https://www.redhat.com/en/topics/virtualization/what-is-a-virtual-machine)

[https://docs.docker.com/get-started/overview/#docker-architecture](https://docs.docker.com/get-started/overview/#docker-architecture)