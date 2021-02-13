---
title: "Help Bears : TryHackMe"
last_modified_at: 2021-02-13
categories:
  - TryHackMe
author_profile: false
tags:
  - Obfuscation
  - steghide
  - JS
  - TryHackMe
---

## Task 1

There is nothing to do here, but this task is needed for the final task.

![](https://cdn-images-1.medium.com/max/2000/1*vajIZZMhv2Erjkx6o88d1A.png)

## Task 2

In this task, the Obfuscated JS needs to be decoded.

![](https://cdn-images-1.medium.com/max/2000/1*ClCNAmOu-EezEl96M4B36Q.png)

Here is the content of the given file

    É=-~-~[],ó=-~É,Ë=É<<É,þ=Ë+~[];Ì=(ó-ó)[Û=(''+{})[É+ó]+(''+{})[ó-É]+([].ó+'')[ó-É]+(!!''+'')[ó]+({}+'')[ó+ó]+(!''+'')[ó-É]+(!''+'')[É]+(''+{})[É+ó]+({}+'')[ó+ó]+(''+{})[ó-É]+(!''+'')[ó-É]][Û];Ì(Ì((!''+'')[ó-É]+(!''+'')[ó]+(!''+'')[ó-ó]+(!''+'')[É]+((!''+''))[ó-É]+([].$+'')[ó-É]+'\''+''+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(þ)+(É+ó)+'\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó-É)+(É+ó)+(É+ó)+'\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(É+ó)+(ó-ó)+'\\'+(É+É)+(þ)+'\\'+(ó-É)+(ó-ó)+(É+ó)+'\\'+(ó-É)+(É+ó)+(ó+ó)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(þ)+(É)+'\\'+(É+É)+(ó-ó)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(É+É)+(ó-ó)+'\\'+(ó-É)+(É+ó)+(É+ó)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(É+É)+(ó-ó)+'\\'+(ó-É)+(É+É)+(É+É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(É+É)+(ó-ó)+'\\'+(ó-É)+(ó+ó)+(ó-ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(ó+ó)+(ó)+'\\'+(ó-É)+(ó+ó)+(ó)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(É+É)+(þ)+'\\'+(É+ó)+(ó-É)+'\\'+(þ)+(ó)+'\\'+(ó-É)+(É+ó)+(ó-É)+'\\'+(ó-É)+(É+É)+(ó+ó)+'\\'+(É+ó)+(ó-ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(þ)+(É+ó)+'\\'+(þ)+(É+ó)+'\\'+(É+É)+(þ)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó+ó)+(ó-É)+'\\'+(ó+ó)+(É)+'\\'+(ó+ó)+(ó)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(É+É)+(þ)+'\\'+(É+ó)+(ó-É)+'\\'+(ó-É)+(þ)+(ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(É+ó)+(ó-ó)+'\\'+(É+É)+(þ)+'\\'+(ó-É)+(É+É)+(É)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(ó+ó)+(ó+ó)+'\\'+(ó-É)+(É+ó)+(þ)+'\\'+(É+É)+(þ)+'\\'+(É+ó)+(ó-É)+'\\'+(þ)+(ó)+'\\'+(ó-É)+(þ)+(É+ó)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(ó+ó)+(ó)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(þ)+(ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(ó-É)+(É+É)+(É+ó)+'\\'+(ó-É)+(ó+ó)+(É)+'\\'+(ó-É)+(ó+ó)+(É+É)+'\\'+(É+ó)+(ó-ó)+'\\'+(É+É)+(þ)+'\\'+(ó-É)+(É+É)+(ó+ó)+'\\'+(ó-É)+(É+É)+(ó-É)+'\\'+(ó-É)+(É+ó)+(ó-É)+'\\'+(ó-É)+(É+ó)+(É+É)+'\\'+(É+ó)+(ó+ó)+'\\'+(É+ó)+(ó+ó)+'\\'+(É+ó)+(ó+ó)+'\\'+(É+É)+(þ)+'\\'+(É+ó)+(ó-É)+'\\'+(þ)+(ó)+'\\'+(ó-É)+(þ)+(É+ó)+'\'')())()

Here the code is obfuscated. We can see a few characters used É, ó, þ, Ì, Û, Ë. Let's beautify the code first and then rename the variables. For beautifying, I used [this](https://beautifier.io/).

Renaming the variables

    É : var1
    ó : var2
    Ë : var3
    þ : var4
    Ì : var5
    Û : var6

On renaming the variables we get

    var1 = -~-~[], var2 = -~var1, var3 = var1 << var1, var4 = var3 + ~[];

    var5 = (var2 - var2)[var6 = ('' + {})[var1 + var2] + ('' + {})[var2 - var1] + ([].var2 + '')[var2 - var1] + (!!'' + '')[var2] + ({} + '')[var2 + var2] + (!'' + '')[var2 - var1] + (!'' + '')[var1] + ('' + {})[var1 + var2] + ({} + '')[var2 + var2] + ('' + {})[var2 - var1] + (!'' + '')[var2 - var1]][var6];

    var5(var5((!'' + '')[var2 - var1] + (!'' + '')[var2] + (!'' + '')[var2 - var2] + (!'' + '')[var1] + ((!'' + ''))[var2 - var1] + ([].$ + '')[var2 - var1] + '\'' + '' + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var4) + (var1 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var2 - var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var2 - var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var1 + var2) + (var2 - var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var2 - var1) + (var2 - var2) + (var1 + var2) + '\\' + (var2 - var1) + (var1 + var2) + (var2 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var4) + (var1) + '\\' + (var1 + var1) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var1 + var1) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var2) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var1 + var1) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var1 + var1) + (var2 - var2) + '\\' + (var2 - var1) + (var2 + var2) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var2 + var2) + (var2) + '\\' + (var2 - var1) + (var2 + var2) + (var2) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var1 + var2) + (var2 - var1) + '\\' + (var4) + (var2) + '\\' + (var2 - var1) + (var1 + var2) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var1) + (var2 + var2) + '\\' + (var1 + var2) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var4) + (var1 + var2) + '\\' + (var4) + (var1 + var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 + var2) + (var2 - var1) + '\\' + (var2 + var2) + (var1) + '\\' + (var2 + var2) + (var2) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var1 + var1) + (var4) + '\\' + (var1 + var2) + (var2 - var1) + '\\' + (var2 - var1) + (var4) + (var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var1 + var2) + (var2 - var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var2 - var1) + (var1 + var1) + (var1) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var2 + var2) + (var2 + var2) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var1 + var1) + (var4) + '\\' + (var1 + var2) + (var2 - var1) + '\\' + (var4) + (var2) + '\\' + (var2 - var1) + (var4) + (var1 + var2) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var2 + var2) + (var2) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var4) + (var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var1 + var2) + (var2 - var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var2 - var1) + (var1 + var1) + (var2 + var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var2) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var1 + var2) + (var2 + var2) + '\\' + (var1 + var2) + (var2 + var2) + '\\' + (var1 + var2) + (var2 + var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var1 + var2) + (var2 - var1) + '\\' + (var4) + (var2) + '\\' + (var2 - var1) + (var4) + (var1 + var2) + '\'')())()

If we paste the code in the chrome developer console, we get an alert asking for a password.

![](https://cdn-images-1.medium.com/max/2000/1*AU1vgDhGhlgCB3ogofZnaQ.png)

![](https://cdn-images-1.medium.com/max/3796/1*Bntk6_g3D9A4W6ezY-fbGA.png)

If the wrong password is given it shows fail. So we need to find what code is running. In order to debug the code, I created an HTML file and added the JS in the script tag so that debugging in chrome developer console could be done.

    <html>

    <script>

    var1 = -~-~[], var2 = -~var1, var3 = var1 << var1, var4 = var3 + ~[];

    var5 = (var2 - var2)[var6 = ('' + {})[var1 + var2] + ('' + {})[var2 - var1] + ([].var2 + '')[var2 - var1] + (!!'' + '')[var2] + ({} + '')[var2 + var2] + (!'' + '')[var2 - var1] + (!'' + '')[var1] + ('' + {})[var1 + var2] + ({} + '')[var2 + var2] + ('' + {})[var2 - var1] + (!'' + '')[var2 - var1]][var6];

    var5(var5((!'' + '')[var2 - var1] + (!'' + '')[var2] + (!'' + '')[var2 - var2] + (!'' + '')[var1] + ((!'' + ''))[var2 - var1] + ([].$ + '')[var2 - var1] + '\'' + '' + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var4) + (var1 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var2 - var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var2 - var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var1 + var2) + (var2 - var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var2 - var1) + (var2 - var2) + (var1 + var2) + '\\' + (var2 - var1) + (var1 + var2) + (var2 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var4) + (var1) + '\\' + (var1 + var1) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var1 + var1) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var2) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var1 + var1) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var1 + var1) + (var2 - var2) + '\\' + (var2 - var1) + (var2 + var2) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var2 + var2) + (var2) + '\\' + (var2 - var1) + (var2 + var2) + (var2) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var1 + var2) + (var2 - var1) + '\\' + (var4) + (var2) + '\\' + (var2 - var1) + (var1 + var2) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var1) + (var2 + var2) + '\\' + (var1 + var2) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var4) + (var1 + var2) + '\\' + (var4) + (var1 + var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 + var2) + (var2 - var1) + '\\' + (var2 + var2) + (var1) + '\\' + (var2 + var2) + (var2) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var1 + var1) + (var4) + '\\' + (var1 + var2) + (var2 - var1) + '\\' + (var2 - var1) + (var4) + (var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var1 + var2) + (var2 - var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var2 - var1) + (var1 + var1) + (var1) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var2 + var2) + (var2 + var2) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var1 + var1) + (var4) + '\\' + (var1 + var2) + (var2 - var1) + '\\' + (var4) + (var2) + '\\' + (var2 - var1) + (var4) + (var1 + var2) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var2 + var2) + (var2) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var4) + (var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var1 + var2) + (var2 - var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var2 - var1) + (var1 + var1) + (var2 + var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var2) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var1 + var2) + (var2 + var2) + '\\' + (var1 + var2) + (var2 + var2) + '\\' + (var1 + var2) + (var2 + var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var1 + var2) + (var2 - var1) + '\\' + (var4) + (var2) + '\\' + (var2 - var1) + (var4) + (var1 + var2) + '\'')())()

    </script>

    </html>

On the chrome developer console, on the sources tab, we can select the HTML file and set a breakpoint. I set two breakpoints and added all variables to the watch section in order to view their values.

![Setting breakpoints and adding variables to watch.](https://cdn-images-1.medium.com/max/3840/1*vPLmajtGN8sgr0WgAPg71Q.png)*Setting breakpoints and adding variables to watch.*

On refreshing the page, we can see the variables being populated.

![](https://cdn-images-1.medium.com/max/3338/1*QcQwrBrkxsFCyf0nVRq4wg.png)

Since the breakpoint is on the second line of JS so the first line sets these values to the variable. On hitting the step over next function button, we get values to var5 and var6.

![](https://cdn-images-1.medium.com/max/2000/1*9a0YApXPBdNBm9cMA9kqrQ.png)

We can replace these values in the HTML file, to make it more readable. Here first line is replaced by values of variables var1,var2,var3,var4,var6.

![Code after replacing variables.](https://cdn-images-1.medium.com/max/2000/1*5l8GRl6E-ZJlnTyLtdYJ_Q.png)*Code after replacing variables.*

Var5 is a function so the last line has arguments to the function, lets try to find, what is exactly running.

If we assign the parameter to a new variable, we can watch the exact parameter that is being passed. After doing that here is a code.

    <html>

    <script>

    var1 = 2;

    var2 = 3;

    var3 = 8;

    var4 = 7;

    var5 = (var2 - var2)[var6 = "constructor"][var6];

    **r**=(!'' + '')[var2 - var1] + (!'' + '')[var2] + (!'' + '')[var2 - var2] + (!'' + '')[var1] + ((!'' + ''))[var2 - var1] + ([].$ + '')[var2 - var1] + '\'' + '' + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var4) + (var1 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var2 - var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var2 - var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var1 + var2) + (var2 - var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var2 - var1) + (var2 - var2) + (var1 + var2) + '\\' + (var2 - var1) + (var1 + var2) + (var2 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var4) + (var1) + '\\' + (var1 + var1) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var1 + var1) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var2) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var1 + var1) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var1 + var1) + (var2 - var2) + '\\' + (var2 - var1) + (var2 + var2) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var2 + var2) + (var2) + '\\' + (var2 - var1) + (var2 + var2) + (var2) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var1 + var2) + (var2 - var1) + '\\' + (var4) + (var2) + '\\' + (var2 - var1) + (var1 + var2) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var1) + (var2 + var2) + '\\' + (var1 + var2) + (var2 - var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var4) + (var1 + var2) + '\\' + (var4) + (var1 + var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 + var2) + (var2 - var1) + '\\' + (var2 + var2) + (var1) + '\\' + (var2 + var2) + (var2) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var1 + var1) + (var4) + '\\' + (var1 + var2) + (var2 - var1) + '\\' + (var2 - var1) + (var4) + (var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var1 + var2) + (var2 - var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var2 - var1) + (var1 + var1) + (var1) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var2 + var2) + (var2 + var2) + '\\' + (var2 - var1) + (var1 + var2) + (var4) + '\\' + (var1 + var1) + (var4) + '\\' + (var1 + var2) + (var2 - var1) + '\\' + (var4) + (var2) + '\\' + (var2 - var1) + (var4) + (var1 + var2) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var2 + var2) + (var2) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var4) + (var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var2 - var1) + (var1 + var1) + (var1 + var2) + '\\' + (var2 - var1) + (var2 + var2) + (var1) + '\\' + (var2 - var1) + (var2 + var2) + (var1 + var1) + '\\' + (var1 + var2) + (var2 - var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var2 - var1) + (var1 + var1) + (var2 + var2) + '\\' + (var2 - var1) + (var1 + var1) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var2) + (var2 - var1) + '\\' + (var2 - var1) + (var1 + var2) + (var1 + var1) + '\\' + (var1 + var2) + (var2 + var2) + '\\' + (var1 + var2) + (var2 + var2) + '\\' + (var1 + var2) + (var2 + var2) + '\\' + (var1 + var1) + (var4) + '\\' + (var1 + var2) + (var2 - var1) + '\\' + (var4) + (var2) + '\\' + (var2 - var1) + (var4) + (var1 + var2) + '\'';

    var5(var5(**r**)())()

    </script>

    </html>

Here, the parameter is assigned to variable r. Now, let's watch the variable r.

![Here a text is returned.](https://cdn-images-1.medium.com/max/3388/1*8k3KonPGkkf0m3OSBpbQ1A.png)*Here a text is returned.*

    "return'\141\75\160\162\157\155\160\164\50\47\105\156\164\162\145\172\40\154\145\40\155\157\164\40\144\145\40\160\141\163\163\145\47\51\73\151\146\50\141\75\75\47\164\157\164\157\61\62\63\154\157\154\47\51\173\141\154\145\162\164\50\47\142\162\141\166\157\47\51\73\175\145\154\163\145\173\141\154\145\162\164\50\47\146\141\151\154\56\56\56\47\51\73\175'"

Now if we paste the result in console, we get

![](https://cdn-images-1.medium.com/max/2000/1*aGpjMABConGhdTClZqlgjw.png)

This way we can get the password.

## Task 3

This is the easiest among all the tasks.

![](https://cdn-images-1.medium.com/max/2000/1*uwuCcVr716fdNao21DZ2Hw.png)

Task 3 is quite easy compared to Task 2. The content in the file

    var pass = unescape("unescape%28%22String.fromCharCode%2528104%252C68%252C117%252C102%252C106%252C100%252C107%252C105%252C49%252C53%252C54%2529%22%29");

The characters seem to be URL encoded. So we need to decode this

    var a ='var pass = unescape("unescape%28%22String.fromCharCode%2528104%252C68%252C117%252C102%252C106%252C100%252C107%252C105%252C49%252C53%252C54%2529%22%29");'
    r =decodeURIComponent(a)
    **/*
    value of r
    "var pass = unescape("unescape("String.fromCharCode%28104%2C68%2C117%2C102%2C106%2C100%2C107%2C105%2C49%2C53%2C54%29")");"
    */**

Some of the characters are decoded, but some are still in the URL encoded form so decoded it again.

    decodeURIComponent(r)
    /*
    "var pass = unescape("unescape("String.fromCharCode(104,68,117,102,106,100,107,105,49,53,54)")");"
    */

On running the output, we get the password.

Task3

![](https://cdn-images-1.medium.com/max/2000/1*aNjfHmAI6ZQX_z_QPHkHXA.png)

Since there was a **steg **tag on the challenge, so there must, be something to do with the image in Task 1. I tried most of the tools in order to extract the data. I failed at all of them. So used **stegcracker** to find the password and extracted the data with **steghide .**

    $ stegcracker bear.jpg /usr/share/wordlists/rockyou.txt

Extracted password as pandas

    $ steghide extract -p pandas -sf bear.jpg
    wrote extracted data to "challenge.txt".

On viewing challenge.txt using cat we just get a word

    $ cat challenge.txt
    Grizzly!

This didn’t make any sense, so used vim to view the file and got some Unicode characters.

    <200c><200c><200c><200c><200d><200c><200d><202c>Grizzly<200c><200c><200c><200c><200d><202c><feff><200c><200c><    200c><200c><200c><200d><202c><200c><200d><200c><200c><200c><200c><200d><202c><200d><feff><200c><200c><200c><20    0c><200c><feff><202c><202c><200c><200c><200c><200c><200c><202c><200c><200c><200c><200c><200c><200c><200c><202c    ><202c><202c><200c><200c><200c><200c><200c><feff><202c><feff><200c><200c><200c><200c><200d><feff><feff><200d><    200c><200c><200c><200c><200c><feff><202c><200d><200c><200c><200c><200c><200c><feff><200d><200c><200c><200c><20    0c><200c><200c><feff><feff><feff><200c><200c><200c><200c><200d><feff><feff><200d><200c><200c><200c><200c><200c    ><feff><200d><feff><200c><200c><200c><200c><200c><202c><202c><feff><200c><200c><200c><200c><200d><200c><202c><    feff><200c><200c><200c><200c><200d><feff><200c><200c><200c><200c><200c><200c><200d><200c><202c><200c><200c><20    0c><200c><200c><200c><feff><200c><feff>!<200c><200c><200c><200c><200c><feff><feff><202c><200c><200c><200c><200    c><200d><feff><200d><200d><200c><200c><200c><200c><200c><feff><200d><feff><200c><200c><200c><200c><200c><feff>    <200d><200c><200c><200c><200c><200c><200d><feff><200d><202c><200c><200c><200c><200c><200d><feff><200d><200c><2    00c><200c><200c><200c><200c><feff><feff><200c><200c><200c><200c><200c><200d><feff><202c><200d><200c><200c><200    c><200c><200d><feff><200d><200d><200c><200c><200c><200c><200d><202c><202c><200c><200c><200c><200c><200c><200d>    <200d><feff><feff><200c><200c><200c><200c><200d><feff><feff><200d><200c><200c><200c><200c><200d><feff><200d><2    02c><200c><200c><200c><200c><200c><202c><200d><feff><200c><200c><200c><200c><200c><feff><200d><feff><200c><200    c><200c><200c><200d><feff><feff><200c><200c><200c><200c><200c><200d><feff><200d><200d><200c><200c><200c><200c>    <200d><feff><feff><200d><200c><200c><200c><200c><200d><feff><200c><feff><200c><200c><200c><200c><200c><202c><2    00d><202c><200c><200c><200c><200c><200d><feff><200c><200c><200c><200c><200c><200c><200d><202c><feff><200c><200    c><200c><200c><200c><200d><202c><feff><200c> ‍‌‌‌‌‍ ‌ ‌‌‌‌‌‬‍‬‌‌‌‌‍ ‌‌‌‌‌‌‍‬ ‌‌‌‌‌‍‬ ‌

On googling around, I found [this](https://330k.github.io/misc_tools/unicode_steganography.html) website which explains Unicode Steganography with Zero-Width Characters. Used this site to decode the text. On directly pasting the characters didn’t work. So, used **xclip** to copy the characters to clipboard and paste the characters there

    $ cat challenge.txt | xclip -selection clipboard

![](https://cdn-images-1.medium.com/max/2000/1*tUWhFr92CZlzdIeRPWxasg.png)

This time I got the flag. But this was not the flag. The text is encoded. So this needs to be decoded to get the flag. In order to decode, we need to find the encoding used. On googling more about ciphers I found [this](http://members.quicknet.nl/nj.vandompselaar/files/prive/converter_for_rot_5_13_18_47.html) website explaining various ROT ciphers.

![](https://cdn-images-1.medium.com/max/2000/1*zxSpv7KidICYf_xrgv4-Jg.png)

The encoded text has the properties of ROT47 cipher. Then I used [this](https://www.dcode.fr/rot-47-cipher) to decode the given text. Again there is no flag but this string

    YjNhcnNfZzAwbmFfcGEkJF90NGVfMFNDUA==

By looking at the == we can know its a base64 encoded string. Decoded it to get the flag.

    $ echo "YjNhcnNfZzAwbmFfcGEkJF90NGVfMFNDUA==" | base64 -d

Finally, this is the flag.

Hope you learned something by reading this writeup. For every JS operation, I used chrome developer console. If you feel anything could be done easily, feel free to suggest.
