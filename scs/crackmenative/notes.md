# Swiss Hacking Challenge 2021 - CTF Bundle 13.3.2021 - CrackMe Native

Task:

This app holds a secret inside. The app is armored with "Anti-Hooking" protection.

Objective: The password is somewhere hidden in this app. Extract it. The password is the flag.

(APK file download link provided in challenge description)

# Intro

This challenge would be solvable with static analysis only (fairly easy). Anyways, I tried to go with a new approach, mostly relying on binary instrumentation with `Frida` and some creative ideas. So this document is more a kind of tutorial on some interesting (and maybe new) Frida techniques. For this reason, I like to ask you if I am allowed to **privately** share the document with the developer of Frida (Ole André V. Ravnås), before it is allowed to be published. Maybe it could serve others as inspiration (I like the idea of free knowledge-sharing), but considering Ole ... I am very interested in his feedback and how things could be further optimized.

Thank you for the challenge.

# Walk-Trough

After unpacking (jadx), there is a single native lib for all major architectures (ARMv7, ARM64, x86 and x86_64).

A quick objdump on the x86_64 version reveals 2 JNI methods

- `Java_org_bfe_crackmenative_ui_LoginViewModel_checkHooking`
- `Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw`

In addition some syscalls, from which the `strstr` comparison deserves the most attention.

```
# objdump -trTR libnative-lib.so

libnative-lib.so:     file format elf64-x86-64

SYMBOL TABLE:
no symbols


DYNAMIC SYMBOL TABLE:
0000000000000000      DF *UND*  0000000000000000  LIBC        __cxa_atexit
0000000000000000      DF *UND*  0000000000000000  LIBC        __cxa_finalize
0000000000000000      DF *UND*  0000000000000000              __android_log_write
0000000000000000      DF *UND*  0000000000000000  LIBC        __stack_chk_fail
0000000000000000      DF *UND*  0000000000000000  LIBC        fclose
0000000000000000      DF *UND*  0000000000000000  LIBC        fgets
0000000000000000      DF *UND*  0000000000000000  LIBC        fopen
0000000000000000      DF *UND*  0000000000000000  LIBC        strstr
0000000000003000 g    D  *ABS*  0000000000000000  Base        _edata
0000000000003000 g    D  *ABS*  0000000000000000  Base        _end
0000000000003000 g    D  *ABS*  0000000000000000  Base        __bss_start
0000000000000810 g    DF .text  00000000000000f9  Base        Java_org_bfe_crackmenative_ui_LoginViewModel_checkHooking
0000000000000910 g    DF .text  0000000000000190  Base        Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw


DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE
0000000000002d70 R_X86_64_RELATIVE  *ABS*+0x0000000000002d70
0000000000002d78 R_X86_64_RELATIVE  *ABS*+0x00000000000007d0
0000000000002d80 R_X86_64_RELATIVE  *ABS*+0x00000000000007b0
0000000000002fc0 R_X86_64_JUMP_SLOT  __cxa_finalize@LIBC
0000000000002fc8 R_X86_64_JUMP_SLOT  __cxa_atexit@LIBC
0000000000002fd0 R_X86_64_JUMP_SLOT  __android_log_write
0000000000002fd8 R_X86_64_JUMP_SLOT  fopen@LIBC
0000000000002fe0 R_X86_64_JUMP_SLOT  fgets@LIBC
0000000000002fe8 R_X86_64_JUMP_SLOT  strstr@LIBC
0000000000002ff0 R_X86_64_JUMP_SLOT  fclose@LIBC
0000000000002ff8 R_X86_64_JUMP_SLOT  __stack_chk_fail@LIBC
```

I assume the hooking protection is based on "self-ptracing", but giving instrumentation a shot should be worth it, anyways.

The app package name is `org.bfe.crackmenative`. A first attempt to launch the app fails, because of implemented root detection.

The root check is implemented on Java-layer, like this:

```
package org.bfe.crackmenative;

import android.content.Context;
import android.os.Build;
import java.io.File;

public class RootCheck {
    public static boolean a() {
        for (String file : System.getenv("PATH").split(":")) {
            if (new File(file, "su").exists()) {
                return true;
            }
        }
        return false;
    }

    public static boolean b() {
        String str = Build.TAGS;
        return str != null && str.contains("test-keys");
    }

    public static boolean c() {
        String[] strArr = {"/system/app/Superuser.apk", "/system/xbin/daemonsu", "/system/etc/init.d/99SuperSUDaemon", "/system/bin/.ext/.su", "/system/etc/.has_su_daemon", "/system/etc/.installed_su_daemon", "/dev/com.koushikdutta.superuser.daemon/"};
        for (int i = 0; i < 7; i++) {
            if (new File(strArr[i]).exists()) {
                return true;
            }
        }
        return false;
    }

    public static boolean checkDebuggable(Context context) {
        return (context.getApplicationContext().getApplicationInfo().flags & 2) != 0;
    }
}
```

This class obviously needs to be hooked once loaded (not loaded at application spawn time).

Let's prepare a development environment for a Frida agent:

```
# frida-create agent
# npm install
# npm run watch
```

The last command constantly re-compiles the JavaScript agent, if the generated TypeScript source file are changed.

Adjusting the "bootstrap code" of `index.ts` to only log libc syscalls to `open` (for a first test of the setup):

```
import { log } from "./logger"

Interceptor.attach(Module.getExportByName(null, "open"), {
  onEnter(args) {
    const path = args[0].readUtf8String()
    log(`open() path="${path}"`)
  },
})
```

... and launching the script in its current compiled version (before the app gets spawned):

```
frida -U -l _agent.js --no-pause -f org.bfe.crackmenative
```

Script output (before the "Device is rooted!" message appears):

```
crackmenative# frida -U -l _agent.js --no-pause -f org.bfe.crackmenative
     ____
    / _  |   Frida 14.2.13 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/
Spawned `org.bfe.crackmenative`. Resuming main thread!
[SM-G900F::org.bfe.crackmenative]-> open() path="/proc/self/cmdline"
open() path="/data/app/org.bfe.crackmenative-Oy1uWjqgLbPPrqlBoXdWPQ==/base.apk.arm.flock"
open() path="/data/app/org.bfe.crackmenative-Oy1uWjqgLbPPrqlBoXdWPQ==/oat/arm/base.vdex"
open() path="/data/app/org.bfe.crackmenative-Oy1uWjqgLbPPrqlBoXdWPQ==/base.apk"
open() path="/system/framework/arm/boot.art"
open() path="/data/dalvik-cache/arm/system@framework@boot.art"
open() path="/data/app/org.bfe.crackmenative-Oy1uWjqgLbPPrqlBoXdWPQ==/oat/arm/base.art"
open() path="/data/app/org.bfe.crackmenative-Oy1uWjqgLbPPrqlBoXdWPQ==/base.apk"
open() path="/data/user_de/0/org.bfe.crackmenative/code_cache/com.android.skia.shaders_cache"
open() path="/data/app/org.bfe.crackmenative-Oy1uWjqgLbPPrqlBoXdWPQ==/lib/arm/libnative-lib.so"
open() path="./adreno_config.txt"
open() path="/data/misc/gpu//adreno_config.txt"
open() path="./yamato_panel.txt"
open() path="/data/misc/gpu//yamato_panel.txt"
open() path="/dev/kgsl-3d0"
open() path="/dev/kgsl-2d0"
open() path="/dev/kgsl-2d1"
open() path="/dev/ion"
open() path="/sys/class/kgsl/kgsl-3d0/gpuclk"
open() path="/data/user_de/0/org.bfe.crackmenative/code_cache/com.android.opengl.shaders_cache"

```

Okay, to hook runtime loaded Java classes, right after they got loaded, one might think `ClassLoader!onLoad` is the way to go, but as I discussed with Ole (the creator of Frida) several times, hooking `onLoad` interferes with Frida's functionality.

Thus I am going to target `ClassLinker!findClass` from `libart.so`. I had good experience with this approach on "Android 9", but I won't go into great detail, as the approach depends on the Android SDK in use on the test-device (Android 9 in my case).

Here is the code to log classes when they get loaded **the first time** (full replacement of `index.ts`):

```
import { log } from "./logger"

const classWasHandled: Set<string> = new Set<string>()

function hookClassLinkerFindClass() {
  // Mangled Cpp name of libart's ClassLinker::FindClass on Android 9:
  // _ZN3art11ClassLinker9FindClassEPNS_6ThreadEPKcNS_6HandleINS_6mirror11ClassLoaderEEE
  const reClassLinkerFindClass = /art[0-9]{1,2}ClassLinker[0-9]{1,2}FindClassE/
  const mLibArt = Module.load("libart.so")
  const relevantExports = mLibArt
    .enumerateExports()
    .filter((ed) => ed.name.match(reClassLinkerFindClass))
  if (relevantExports.length <= 0) {
    console.log("ERROR: Can not hook ClassLinker::findClass")
  }

  // ToDo: findClass is more re-entrant than loadClass, hooking should be done only once
  Interceptor.attach(relevantExports[0].address, {
    onEnter(args) {
      this.name = args[2].readUtf8String()
    },
    onLeave(res) {
      if (classWasHandled.has(this.name)) return // assure class is only processed for first successful findClass

      if (res.toInt32() !== 0) {
        // if class found
        classWasHandled.add(this.name)
        // return value is of type ObjPtr<mirror::Class>, but we do not care for this, as we move back to frida-java-bridge here
        // Ref: https://android.googlesource.com/platform/art/+/master/runtime/mirror/class.h
        let tmp = (this.name as string).match(/^L(.*);$/) // ignores array classes and primitive types
        if (tmp !== null && tmp.length > 1) {
          const readableName = tmp[1].replace(/\//g, ".")

          if (readableName.startsWith("org.bfe.crackmenative")) {
            console.log(
              "!!!!!!!!!!! ClassLinker::findClass readable name:",
              readableName
            )

            //onNewClassLoaded(readableName)
          }
        }
      }
    },
  })
}

hookClassLinkerFindClass()
```

Running the new script shows, that `org.bfe.crackmenative.RootCheck` is the first class which gets loaded from the `org.bfe.crackmenative` namespace:

```
# frida -U -l _agent.js --no-pause -f org.bfe.crackmenative
     ____
    / _  |   Frida 14.2.13 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/
Spawning `org.bfe.crackmenative`...

Spawned `org.bfe.crackmenative`. Resuming main thread!
[SM-G900F::org.bfe.crackmenative]->
[SM-G900F::org.bfe.crackmenative]->
[SM-G900F::org.bfe.crackmenative]-> !!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.RootCheck
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity$1
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginViewModelFactory
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginViewModel
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity$2
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity$3
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity$4
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity$5
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity$6

```

So let's quickly adjust the script to hook the `RootCheck` class right after it gets loaded and replace the method `a`, `b`, `c` and `checkDebuggable` with a function which always returns false.

```
import { log } from "./logger"

const classWasHandled: Set<string> = new Set<string>()

function hookClassLinkerFindClass() {
  // Mangled Cpp name of libart's ClassLinker::FindClass on Android 9:
  // _ZN3art11ClassLinker9FindClassEPNS_6ThreadEPKcNS_6HandleINS_6mirror11ClassLoaderEEE
  const reClassLinkerFindClass = /art[0-9]{1,2}ClassLinker[0-9]{1,2}FindClassE/
  const mLibArt = Module.load("libart.so")
  const relevantExports = mLibArt
    .enumerateExports()
    .filter((ed) => ed.name.match(reClassLinkerFindClass))
  if (relevantExports.length <= 0) {
    console.log("ERROR: Can not hook ClassLinker::findClass")
  }

  // ToDo: findClass is more re-entrant than loadClass, hooking should be done only once
  Interceptor.attach(relevantExports[0].address, {
    onEnter(args) {
      this.name = args[2].readUtf8String()
    },
    onLeave(res) {
      if (classWasHandled.has(this.name)) return // assure class is only processed for first successful findClass

      if (res.toInt32() !== 0) {
        // if class found
        classWasHandled.add(this.name)
        // return value is of type ObjPtr<mirror::Class>, but we do not care for this, as we move back to frida-java-bridge here
        // Ref: https://android.googlesource.com/platform/art/+/master/runtime/mirror/class.h
        let tmp = (this.name as string).match(/^L(.*);$/) // ignores array classes and primitive types
        if (tmp !== null && tmp.length > 1) {
          const readableName = tmp[1].replace(/\//g, ".")

          if (readableName.startsWith("org.bfe.crackmenative")) {
            console.log(
              "!!!!!!!!!!! ClassLinker::findClass readable name:",
              readableName
            )

            onNewClassLoaded(readableName)
          }
        }
      }
    },
  })
}

function onNewClassLoaded(className: string) {
  if (className.indexOf("RootCheck") > 0) {
    // get handle to the class
    let clzRootCheck = Java.use(className)

    // always return false for RootCheck.a()
    clzRootCheck.a.implementation = function () {
      return false
    }
    // always return false for RootCheck.b()
    clzRootCheck.b.implementation = function () {
      return false
    }
    // always return false for RootCheck.c()
    clzRootCheck.c.implementation = function () {
      return false
    }
    // always return false for RootCheck.checkDebuggable()
    clzRootCheck.checkDebuggable.implementation = function () {
      return false
    }
  }
}

hookClassLinkerFindClass()

```

Once the app is re-spawned with the script, the error dialog complaining about a rooted device is gone. Nice!

The good thing about Frida's inner design, we could attach multiple agents to a single process. So nothing prevents us from running `frida-trace` in addition, in order to monitor the calls to `strstr`. The following command does that, while it attaches to the app running in the foreground:

```
# frida-trace -U -i 'strstr' -F
Instrumenting...
strstr: Loaded handler at "/tmp/__handlers__/libc.so/strstr.js"
Started tracing 1 function. Press Ctrl+C to stop.
           /* TID 0x71f7 */
  4327 ms  strstr(haystack="12c00000-14680000 rw-p 00000000 00:04 12380      /dev/ashmem/dalvik-main space (region space) (deleted)
", needle="Xposed")
  4327 ms  strstr(haystack="12c00000-14680000 rw-p 00000000 00:04 12380      /dev/ashmem/dalvik-main space (region space) (deleted)
", needle="frida")
  4327 ms  strstr(haystack="14680000-14b00000 rw-p 01a80000 00:04 12380      /dev/ashmem/dalvik-main space (region space) (deleted)
", needle="Xposed")
  4327 ms  strstr(haystack="14680000-14b00000 rw-p 01a80000 00:04 12380      /dev/ashmem/dalvik-main space (region space) (deleted)
", needle="frida")
  4327 ms  strstr(haystack="14b00000-18480000 ---p 01f00000 00:04 12380      /dev/ashmem/dalvik-main space (region space) (deleted)
", needle="Xposed")
  4327 ms  strstr(haystack="14b00000-18480000 ---p 01f00000 00:04 12380      /dev/ashmem/dalvik-main space (region space) (deleted)
", needle="frida")
  4327 ms  strstr(haystack="18480000-2ac00000 rw-p 05880000 00:04 12380      /dev/ashmem/dalvik-main space (region space) (deleted)
", needle="Xposed")
  4328 ms  strstr(haystack="18480000-2ac00000 rw-p 05880000 00:04 12380      /dev/ashmem/dalvik-main space (region space) (deleted)
", needle="frida")
  4328 ms  strstr(haystack="70985000-70ba8000 rw-p 00000000 b3:1a 277990     /data/dalvik-cache/arm/system@framework@boot.art

... snip ....
```

The output from `frida-trace` (with the `strstr`) function hooked, draws a clear picture. The native string comparison is applied to
each line of the process memory mapping (either from `/proc/self/maps` or `/proc/<id>/maps`) to search for occurences of `frida` or `Xposed`.

Now we have multiple ways to bypass this:

- redirect the `open` call for `/proc/self/maps` to another file
- intercept `read` to replace occurrences of the aforementioned search-strings whenever they appear
- intercept `strstr` to return "false" when `needle=Xposed` or `needle=frida`

Before moving on, let's hook the `open` syscall to be sure that `/proc/self/maps/` gets opened, at all:

```
# frida-trace -U -i 'open' -F
Instrumenting...
open: Auto-generated handler at "/tmp/__handlers__/libc.so/open.js"
Started tracing 1 function. Press Ctrl+C to stop.
           /* TID 0x71f7 */
  9925 ms  open(pathname="/proc/self/maps", flags=0x0)
 10168 ms  open(pathname="/proc/self/maps", flags=0x0)
```

Now, that was a hit! Let's deal with this in the script:

```
... snip ...

function bypassHookingDetection() {
  let fOpen = Module.getExportByName("libc.so", "open")

  Interceptor.attach(fOpen, {
    onEnter(args) {
      let path = args[0].readUtf8String()
      console.log(path)
      if (path === "/proc/self/maps") {
        let newPath = Memory.allocUtf8String("/proc/self/limits") // just open 'limits' instead of 'maps' ... and there will be no Frida
        this.keepTillInvocationEnd = newPath // hack: bind allocated Memory with new string to this object (survives till invocation end)
        args[0] = newPath
      }
    },
  })
  //Interceptor.attach
}

hookClassLinkerFindClass()
bypassHookingDetection()
```

So the new method `bypassHookingDetection` replaces the argument to `open` with `/proc/self/limits` in case it is `/proc/self/maps`.

With the updated script, the "Stop Hooking" error in the app is immediately gone (without even restarting it, I love the hot-agent-reload of Frida).

The next step would be to hook the `checkPw` function either on Java layer in `org.bfe.crackmenative.ui.LoginViewModel` or on the native layer in `libnative_lib.so` with the function name `Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw`.

Hooking on the Java layer would not be worth much, as the function only servers as interface. The native entrypoint `Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw` follows JNI naming convention for static JNI registration (no `registerNatives`, no `JNI_onLoad`). This means the function receives a pointer to the `JNIenv` and a `jobject` representing the instance, followed by the actual parameters. Because of this, we would have to utilize the JNIenv to translate the references to Java objects from the call args, to actual native objects, if we hook the native method. It would be better to do a quick static analysis on the function code, in order to find a more valuable native hooking target, which already works with native argument representation (inner call).

Before doing so, it is still worth to have a look into `org.bfe.crackmenative.ui.LoginViewModel` because the class also holds a pre-processing method, which translates the user input to an xor encrypted `int[]`. Below an excerpt of the respective function, which is called `getCode` (and the reverse function, which is called `getStringFromCode`):

```
    protected static int[] x0 = {121, 134, 239, 213, 16, 28, 184, 101, 150, 60, 170, 49, 159, 189, 241, 146, 141, 22, 205, 223, 218, 210, 99, 219, 34, 84, 156, 237, 26, 94, 178, 230, 27, 180, 72, 32, 102, 192, 178, 234, 228, 38, 37, 142, 242, 142, 133, 159, 142, 33};

...snip...

    /* access modifiers changed from: protected */
    public int[] getCode(String str) {
        byte[] bytes = str.getBytes();
        int[] iArr = new int[str.length()];
        for (int i = 0; i < str.length(); i++) {
            iArr[i] = bytes[i] ^ x0[i];
        }
        return iArr;
    }

    /* access modifiers changed from: protected */
    public String getStringFromCode(int[] iArr) {
        byte[] bArr = new byte[iArr.length];
        for (int i = 0; i < iArr.length; i++) {
            bArr[i] = (byte) (iArr[i] ^ x0[i]);
        }
        return new String(bArr);
    }
```

For the native perspectiv, it is time to throw `libnative_lib.so` into Ghidra (in my case the ARMv7a version, as it applies to the architecture of my test device).

The Ghidra built-in decompiler does a decent job, yet the generated pseudo-C code is not very readable, as Ghidra does not know about JNI-types by default:

```
undefined4
Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw
          (int *param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  uint *puVar2;
  uint *puVar3;
  bool bVar4;
  undefined4 uVar5;
  int iVar6;
  FILE *__stream;
  char *pcVar7;
  uint *puVar8;
  int iVar9;
  undefined4 uVar10;
  uint uVar11;
  char acStack4140 [4096];
  int iStack44;

  iStack44 = __stack_chk_guard;
  __android_log_write(4,"Native Check","Checking password ...");
  uVar5 = (**(code **)(*param_1 + 0x2cc))(param_1,0);
  iVar6 = (**(code **)(*param_1 + 0x2ac))(param_1,param_3);
  uVar10 = uVar5;
  if (iVar6 == 0x1b) {
    __stream = fopen("/proc/self/maps","r");
    do {
      pcVar7 = fgets(acStack4140,0x1000,__stream);
      if (pcVar7 == (char *)0x0) {
        bVar4 = false;
        goto LAB_00010a32;
      }
      pcVar7 = strstr(acStack4140,"Xposed");
    } while ((pcVar7 == (char *)0x0) &&
            (pcVar7 = strstr(acStack4140,"frida"), pcVar7 == (char *)0x0));
    bVar4 = true;
LAB_00010a32:
    if (__stream != (FILE *)0x0) {
      fclose(__stream);
    }
    if (!bVar4) {
      iVar9 = 0;
      iVar6 = (**(code **)(*param_1 + 0x2ec))(param_1,param_3,0);
      puVar8 = &DAT_00012a60;
      do {
        uVar10 = param_3;
        if (iVar9 == 0x1b) break;
        iVar1 = iVar9 * 4;
        puVar2 = &DAT_000128f8 + iVar9;
        uVar11 = *puVar8;
        puVar3 = &DAT_00012a94 + iVar9;
        iVar9 = iVar9 + 1;
        puVar8 = puVar8 + -1;
        uVar10 = uVar5;
      } while ((*(uint *)(iVar6 + iVar1) ^ *puVar2 ^ uVar11) == *puVar3);
    }
  }
  if (__stack_chk_guard == iStack44) {
    return uVar10;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Let's improve this by introducing proper JNI types to Ghidra's "Data Type Manager" and adjusting the function signature to:

```
jintArray Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw (JNIEnv * env, jobject thiz, jintArray iArr)
```

The decompiled code looks much better now:

```

jintArray Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw
                    (JNIEnv *env,jobject thiz,jintArray iArr)

{
  uint *puVar1;
  uint *puVar2;
  uint *puVar3;
  bool bVar4;
  jintArray p_Var5;
  jsize jVar6;
  FILE *__stream;
  char *pcVar7;
  jint *pjVar8;
  uint *puVar9;
  int iVar10;
  jintArray p_Var11;
  uint uVar12;
  char acStack4140 [4096];
  int iStack44;

  iStack44 = __stack_chk_guard;
  __android_log_write(4,"Native Check","Checking password ...");
  p_Var5 = (*(*env)->NewIntArray)(env,0);
  jVar6 = (*(*env)->GetArrayLength)(env,(jarray)iArr);
  p_Var11 = p_Var5;
  if (jVar6 == 0x1b) {
    __stream = fopen("/proc/self/maps","r");
    do {
      pcVar7 = fgets(acStack4140,0x1000,__stream);
      if (pcVar7 == (char *)0x0) {
        bVar4 = false;
        goto LAB_00010a32;
      }
      pcVar7 = strstr(acStack4140,"Xposed");
    } while ((pcVar7 == (char *)0x0) &&
            (pcVar7 = strstr(acStack4140,"frida"), pcVar7 == (char *)0x0));
    bVar4 = true;
LAB_00010a32:
    if (__stream != (FILE *)0x0) {
      fclose(__stream);
    }
    if (!bVar4) {
      iVar10 = 0;
      pjVar8 = (*(*env)->GetIntArrayElements)(env,iArr,(jboolean *)0x0);
      puVar9 = &DAT_00012a60;
      do {
        p_Var11 = iArr;
        if (iVar10 == 0x1b) break;
        puVar1 = (uint *)(pjVar8 + iVar10);
        puVar2 = &DAT_000128f8 + iVar10;
        uVar12 = *puVar9;
        puVar3 = &DAT_00012a94 + iVar10;
        iVar10 = iVar10 + 1;
        puVar9 = puVar9 + -1;
        p_Var11 = p_Var5;
      } while ((*puVar1 ^ *puVar2 ^ uVar12) == *puVar3);
    }
  }
  if (__stack_chk_guard == iStack44) {
    return p_Var11;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}


```

After renaming a few variables, we got everything we need:

```

jintArray Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw
                    (JNIEnv *env,jobject thiz,jintArray iArr)

{
  uint *puVar1;
  jintArray p_Var4;
  jsize inputLen;
  FILE *__stream;
  char *pcVar5;
  jint *pJint_iArr_nocopy;
  uint *puVar6;
  int pos;
  jintArray p_Var6;
  uint uVar7;
  char acStack4140 [4096];
  int iStack44;
  bool bIsHooked;
  uint *puVar2;
  uint *puVar3;

  iStack44 = __stack_chk_guard;
  __android_log_write(4,"Native Check","Checking password ...");
  p_Var4 = (*(*env)->NewIntArray)(env,0);
  inputLen = (*(*env)->GetArrayLength)(env,(jarray)iArr);
                    /* length of iArr hast to be 27, before the logic runs
                        */
  p_Var6 = p_Var4;
  if (inputLen == 0x1b) {
    __stream = fopen("/proc/self/maps","r");
    do {
      pcVar5 = fgets(acStack4140,0x1000,__stream);
      if (pcVar5 == (char *)0x0) {
        bIsHooked = false;
        goto LAB_00010a32;
      }
      pcVar5 = strstr(acStack4140,"Xposed");
    } while ((pcVar5 == (char *)0x0) &&
            (pcVar5 = strstr(acStack4140,"frida"), pcVar5 == (char *)0x0));
    bIsHooked = true;
LAB_00010a32:
    if (__stream != (FILE *)0x0) {
      fclose(__stream);
    }
    if (!bIsHooked) {
      pos = 0;
      pJint_iArr_nocopy = (*(*env)->GetIntArrayElements)(env,iArr,(jboolean *)0x0);
      puVar6 = (uint *)&end_of_uint_array;
      do {
                    /* Stop when counter var reaches 27 (end of iArr) */
        p_Var6 = iArr;
        if (pos == 0x1b) break;
        puVar1 = (uint *)(pJint_iArr_nocopy + pos);
        puVar2 = UINT_ARRAY_1 + pos;
        uVar7 = *puVar6;
        puVar3 = uint_array_2 + pos;
        pos = pos + 1;
        puVar6 = puVar6 + -1;
        p_Var6 = p_Var4;
      } while ((*puVar1 ^ *puVar2 ^ uVar7) == *puVar3);
    }
  }
  if (__stack_chk_guard == iStack44) {
    return p_Var6;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

If the "hook checks" do not trigger (we already took care of this) and the input length of the `int[]` provided to `checkPw` equals `27` (`0x1b`), the inner xor logic will run:

```
    if (!bIsHooked) {
      pos = 0;
      pJint_iArr_nocopy = (*(*env)->GetIntArrayElements)(env,iArr,(jboolean *)0x0);
      puVar6 = (uint *)&end_of_uint_array;
      do {
                    /* Stop when counter var reaches 27 (end of iArr) */
        p_Var6 = iArr;
        if (pos == 0x1b) break;
        puVar1 = (uint *)(pJint_iArr_nocopy + pos);
        puVar2 = UINT_ARRAY_1 + pos;
        uVar7 = *puVar6;
        puVar3 = uint_array_2 + pos;
        pos = pos + 1;
        puVar6 = puVar6 + -1;
        p_Var6 = p_Var4;
      } while ((*puVar1 ^ *puVar2 ^ uVar7) == *puVar3);
    }
```

The logic is simple:

- the loop aborts when the counter `pos` reaches 27 (the expected input array length)
- `puVar1` points to an integer of the input array, for each loop iteration (pointer incremented by 1 per iteration)
- `puVar2` points to an integer in a static `uint[]`, which I denoted `UINT_ARRAY_1` (pointer incremented by 1 per iteration)
- `puVar3` points to an integer in a static `uint[]`, which I denoted `uint_array_2` (pointer incremented by 1 per iteration)
- `uVar7` holds a value from a static `uint[]` which is dereferenced from the pointer `puVar6`, which starts at the end of the array (denoted as `end_of_uint_array`) and gets decremented by 1 per loop iteration

So the check at the end of the while loop (done per input integer), translates to this pseudo code:

```
input[i] ^ UINT_ARRAY_1[i] ^ *(end_of_uint_array - i) == uint_array_2[i]
```

For the return value of `checkPw` there is another simple logic. The return value is driven by `p_Var6` which is a reference to a `jintArray`. At the beginning of the `checkPw` function, a zero-length array is created. At the beginning of each iteration of the "xor check loop", the return value `p_Var6` gets set to the provided input array, but if the code passes behind the abort condition `if (pos == 0x1b) break;`, the reference `p_Var6` is set back to the new empty array, which was created at function entry. This means, `checkPw` always returns a zero-length array, unless the inner abort condition of the loop is met (early out), which again only happens if the aforementioned "xor check" passes till the last input integer (position 27) is reached.

At this point, we could easily solve the task, by calculating the following for each int at position `i`

```
desired_int[i] = UINT_ARRAY_1[i] ^ *(end_of_uint_array - i) ^ uint_array_2[i]
```

The resulting array `desired_int[27]` would the have to be post processed according to the xor logic of the Java layer function `getStringFromCode`.

I still do not like the idea of solving this statically, as Frida is already in place. That's the reason why I haven't included the 3 aforementioned `uint_t[27]` arrays in this write-up: I want a creative and new way to solve this, otherwise it would be too easy. Let's continue with a binary instrumentation approach relying on Frida (this great tool deserves to be used for other things than CertPinning- and root-detection-bypasses).

Okay, the code design poses some challenges:

- there is no inner, more granular function call to hook with Frida
- there is no (easy) way to brute-force the logic (solving with input adjusted char-by-char), because with function level hooking we are bound to the `checkPw` return value, which has no indication on which loop iteration the internal xor-check failed (return value only changes if the full loop passes).

There are two major possibilities which could help to apply a brute-force attempt, anyways:

1. A timing based attack, to measure how much time `checkPw` spent on the inner loop, while adjusting the input of the `int[]`carefully, starting from position 0 (I love this idea).
2. Utilizing Frida's `Stalker` API, which works on per instruction level and allows tracing and manipulation of single instructions.

The second idea did not work out, because Frida's stalker still works on "compiled code block level" (call block), for which instructions could be manipulated **before they get executed**, but it is not inteded for instruction-level runtime tracing.

The first idea has some hurdles, too: If the function `checkPw` gets called from Java layer, there is just too much (inconsitent) JNI overhead, to measure significant timing differences for changing input (even with thousands of calls per input test-set). Monitoring the execution time of native `Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw` for different inputs, woulde maybe work, but I haven't found a way to utilize a high performance timer from the Frida agent - only `Date.now()` seems to be available (tested only for QuickJS runtime). The timer is way to inacurate to measure execution time difference for an additional iteration of the inner "do-while-loop". Also, calling the native function with different parameters is more complex, then simply providing a custom input array on the Java-layer. This is, because on the native layer, the expected input still is a `jintArray` (a native representation of a Java runtime type). Contructing or manipulating the input for the JNI function, thus requires uitlizing JNIenv-functionality which adds too much coding overhead.

But hey, that's not the end - nothing is lost. I got another idea:

Without a complete understanding of the low-level magic deployed by Frida, it should still be clear that for hooking, code gets overwritten at runtime (including JIT code) at the desired hooking address. This is done in order to redirect execution to a trampoline function, which mimics the functionality of the just overwritten code, before user provided instrumentation code is executed. If nothing goes wrong, the hooked Process/Thread could continue execution right where it was left (thanks to the trampoline). The Frida API-interface for such tasks is called `Interceptor` - or `Interceptor.attach()` to be specific. Usually this technique is used to place hooks at function entry points (even Java-layer hooking is internally done following this approach, on the native layer with an additional `java-bridge` in between for "on-the-fly-translation"). Anyways, hooking following this "trampoline approach" should be possible on all executable code addresses (matching a instruction address). But, bot placing a hook on a function entry, would of course mess with the API parts which parse and replace function pareameter depending on the calling convention in use (if we do not hook a function entry, it is unlikely that stack and registers look the same as when the function just gets called).

The basic idea of hooking an arbitrary instruction, would still suite our needs if we do not care for call arguments (stack and registers), but only want to trace how often a certain instruction at a given code offset is executed instead (_note: Firda has MemoryAccessMonitor, which could help to find out how often a memory range gets accessed, but I failed with this too as it is not precise enough, thus my scope remains on instruction level_).

So this could be applied to our problem, in order to run a brute force attack. Let's recall the code snippet of the inner loop of native `checkPw` to our minds:

```
    if (!bIsHooked) {
      pos = 0;
      pJint_iArr_nocopy = (*(*env)->GetIntArrayElements)(env,iArr,(jboolean *)0x0);
      puVar6 = (uint *)&end_of_uint_array;
      do {
                    /* Stop when counter var reaches 27 (end of iArr) */
        p_Var6 = iArr;
        if (pos == 0x1b) break;
        puVar1 = (uint *)(pJint_iArr_nocopy + pos);
        puVar2 = UINT_ARRAY_1 + pos;
        uVar7 = *puVar6;
        puVar3 = uint_array_2 + pos;
        pos = pos + 1;
        puVar6 = puVar6 + -1;
        p_Var6 = p_Var4;
      } while ((*puVar1 ^ *puVar2 ^ uVar7) == *puVar3); // <--- trace call count here
    }
```

I marked the relevant position in the high-level pseudo code: The abort condition of the while loop.

The function checks the input `int[27]` array position-by-position, starting from the `int` at position `0`. In addition, it is pretty obvious that the integres only represent values in range of a `byte` as the `getStringFromCode` simply casts them to bytes. Now let's assume we want to brute force the byte at position 0 (I use `byte` and `int` interchangebly, as the represented value never exceeds the range of a byte), which has to be provided as input in order to pass the check.
If we pass in an input buffer with a wrong value at position 0, the condition at the end of the "do-while-loop" is hit exactly once. If we pass in an input buffer with the correct value, the "while-condition" is reached twice, as the loop will progress to the next input position.

Now if we call the `checkPw` function 256-times, with a different `int` value at position 0 of the input buffer (in range `0x00 <= input[0] <= 255`), while tracing the call count for the "do-while-condition check", we would get a call count of `1` for `255 out of 256` tests and a call count `>1` for `1 out of 256` tests (call count should be 2, but could be large if successor bytes were chosen correctly by coincidence). So there exists an easy way to bruteforce a expected value at poistion `0` of the input buffer, with no more than 256 calls to `checkPw`, if we could measure the hit count at the instruction representing the conditional branch for the "do-while-condition". This could be optimized less than 256 test calls, with an eraly out (if the instruction was hit more often than by the previous test), but such optimizations are not necessary - the additional time required to test the complete byte-value range is negligible.

Now with that the value at position 0 was obtained, we could continue with position 1. The new input buffer gets set to the determined value for position 0 and we run 256 tests, where position 1 gets changed. This time the while condition will be hit 2-times for all values at position 1 which are wrong and more often than 2-times for the test with the correct value. So the condition could be generalized to: The input value which hits the "do-while-condition" most often for an input position `i` in the buffer, is the correct one, provided that all values on positions `<i` are already correct. If bruteforce the input buffer postion-by-position, it requires `buffer_length * value_range` attempts at maximum to restore the full expected input array. For our case this means `27 * 256 == 6912` test calls (again, no need to optimize the approach with early outs).

So how did I utilize Frida to implement this approach:

1. As already mentioned, it is easier to provide `int[]` with arbitrary data as argument for `checkPw` from the Java layer, thus the Java function gets hooked first.
2. The Java implementation of `checkPw` gets replaced completly, to carry out all necessary tests, by calling to the legacy `checkPw` function multiple times (once the `checkPw` function is triggered the first time, by real user input. This user input is replaced by arbitrary input for the brute-force tests.)
3. The Java replacement function holds an "invocation counter", which gets reset to 0 before every test-call to the unmodified Java `checkPw` function.
4. At the point in time, when the Java function can be hooked (early at class loading of `LoginViewModel`), the class loader also executes the `static {}` code block, which loads the native library `libnative-lib.so`. As this doesn't happen immediately, the hooking code runs remains in a loop till the module is loaded and available for hooking.
5. Once the native module is loaded, it gets enumerated for the runtime address of the exported function `Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw`. The determined runtime address is increased by the **known offset of the instruction we want to trace (conditional branch of do-while-loop) from the function entry address.** This offset depends on the native library in use and thus on the architecture (in addition on ARMv7a it has to be taken into account that Thumbs instruction are at `instruction address+1`). This also means, the final script has to be adjusted in order to deploy it to different architectures.
6. The, now calculated, instruction address gets hooked, too. While the Java-layer hook homes most of the logic, the native hook only increments the "invocation counter" each time it gets hit (no interaction with call parameters, as they are not valid at this point). _Note: The scope of the "invocation counter" which is named `while_invocation_counter` in my Frida agent i chosen in such a manner, that it could be modified from the Java hook and the native hook - there is no need to deal with concurrent access, as the native function is only called by the Java function, which we invoke ourself._
7. From the perspective of the Java layer hook, the "invocation counter" increased "magically" for each call to the legacy `checkPw` function and thus gets read back and evaluated, before the function is called the next time and the invocation counter gets reset to 0, again. Evaluated, in this case, means that the logi keeps track of all "invocation counts" and the respective value to test, in order to determin which value fort this input buffer position reached the highest count.
8. The described functionality on the Java layer is wrapped into an outer loop, which steps over the range of the whole input buffer, till the last poisition is reconstructed (27 values).
9. The Java layer logic always preserves the return value for the last call to the legacy `checkPw` function. Once the brute-force logic is done, the return value should reflect the input buffer. This value is now passed up to the caller, effectively solving the challenge. There is no need to put the result through `getStringFromCode`. This is, because to the caller, it looks like the correct input was provided by the application. The application logic will do the rest for us and output the result of `getStringFromCode` as toast message.

To trigger the brute-force, the initial input checks have to pass, in order to unlock the `Login` button (which calls `checkPw`). I have not put any effort into bypassing those checks, as it is very simple to provide valid input like `HL{}` to unlock the `Login` button and trigger the "exploit".

Resulting flag: **HL{J4v4.nativ3.d0.n0t.c4r3}**

The remaining section cover the full source code of the script (including comment), the offset calculation for the native library I used and a link to a youtube video, which shows the script in action (only accessible with known link).

# How the offset to the relevant instruction was determined (ARMv7a only):

Function disassembly:

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             jintArray __stdcall Java_org_bfe_crackmenative_ui_LoginV
                               assume LRset = 0x0
                               assume TMode = 0x1
             jintArray         r0:4           <RETURN>
             JNIEnv *          r0:4           env                                     XREF[5]:     000109d8(W),
                                                                                                   000109e8(W),
                                                                                                   000109f8(W),
                                                                                                   00010a10(W),
                                                                                                   00010a50(W)
             jobject           r1:4           thiz                                    XREF[1]:     00010a60(W)
             jintArray         r2:4           iArr
             undefined4        r0:4           p_Var4                                  XREF[1]:     000109d8(W)
             undefined4        r0:4           inputLen                                XREF[1]:     000109e8(W)
             undefined4        r0:4           __stream                                XREF[1]:     000109f8(W)
             undefined4        r0:4           pcVar5                                  XREF[1]:     00010a10(W)
             undefined4        r4:4           pos                                     XREF[1]:     00010a48(W)
             undefined4        r0:4           pJint_iArr_nocopy                       XREF[1]:     00010a50(W)
             uint *            r1:4           puVar6                                  XREF[1]:     00010a60(W)
             undefined4        r6:4           uVar7                                   XREF[1]:     00010a6e(W)
             undefined4        r4:4           p_Var6                                  XREF[1]:     00010a84(W)
             undefined4        Stack[-0x2c]:4 iStack44
             undefined1[409    Stack[-0x102   acStack4140
             undefined4        Stack[-0x103   local_1030                              XREF[2]:     000109ee(W),
                                                                                                   00010a7e(R)
             undefined1        HASH:79f9d13   bIsHooked
             undefined4        HASH:413d5fe   puVar1Input
             undefined4        HASH:83f6db5   puVar2
             undefined4        HASH:83f4ae8   puVar3
                             puInput                                         XREF[1]:     Entry Point(*)
                             Java_org_bfe_crackmenative_ui_LoginViewModel_c
--> function entry
        0001099c f0 b5           push       { r4, r5, r6, r7, lr }
        0001099e 03 af           add        r7,sp,#0xc
        000109a0 2d e9 00 0f     push       { r8, r9, r10, r11  }
        000109a4 ad f5 80 5d     sub.w      sp,sp,#0x1000
        000109a8 83 b0           sub        sp,#0xc
        000109aa 82 46           mov        r10,env
        000109ac 3d 48           ldr        env,[DAT_00010aa4]                               = 000035ECh
        000109ae 91 46           mov        r9,iArr
        000109b0 78 44           add        env,pc
        000109b2 d0 f8 00 80     ldr.w      r8,[env,#0x0]=>->__stack_chk_guard               = 00015014
        000109b6 d8 f8 00 00     ldr.w      env,[r8,#0x0]=>__stack_chk_guard                 = ??
        000109ba 47 f8 24 0c     str.w      env,[r7,#-0x24]
        000109be 04 20           mov        env,#0x4
        000109c0 39 49           ldr        thiz,[DAT_00010aa8]                              = 00001A5Dh
        000109c2 3a 4a           ldr        iArr,[DAT_00010aac]                              = 00001A68h
        000109c4 79 44           add        thiz=>s_Native_Check_00012425,pc                 = "Native Check"
        000109c6 7a 44           add        iArr=>s_Checking_password_..._00012432,pc        = "Checking password ..."
        000109c8 ff f7 0a ef     blx        __android_log_write                              undefined __android_log_write()
        000109cc da f8 00 00     ldr.w      env,[r10,#0x0]
        000109d0 00 21           mov        thiz,#0x0
        000109d2 d0 f8 cc 22     ldr.w      iArr,[env,#0x2cc]
        000109d6 50 46           mov        env,r10
        000109d8 90 47           blx        iArr
        000109da 04 46           mov        r4,p_Var4
        000109dc da f8 00 00     ldr.w      p_Var4,[r10,#0x0]
        000109e0 49 46           mov        thiz,r9
        000109e2 d0 f8 ac 22     ldr.w      iArr,[p_Var4,#0x2ac]
        000109e6 50 46           mov        p_Var4,r10
        000109e8 90 47           blx        iArr
                             length of iArr hast to be 27, before the logic runs
        000109ea 1b 28           cmp        inputLen,#0x1b
        000109ec 4a d1           bne        LAB_00010a84
        000109ee 00 94           str        r4,[sp,#0x0]=>local_1030
        000109f0 2f 48           ldr        inputLen,[DAT_00010ab0]                          = 00001A50h
        000109f2 30 49           ldr        thiz,[DAT_00010ab4]                              = 00001A5Eh
        000109f4 78 44           add        inputLen=>s_/proc/self/maps_00012448,pc          = "/proc/self/maps"
        000109f6 79 44           add        thiz=>DAT_00012458,pc                            = 72h    r
        000109f8 ff f7 f8 ee     blx        fopen                                            FILE * fopen(char * __filename,
        000109fc 2e 4e           ldr        r6,[DAT_00010ab8]                                = 00001A52h
        000109fe 01 ac           add        r4,sp,#0x4
        00010a00 2e 4d           ldr        r5,[DAT_00010abc]                                = 00001A57h
        00010a02 83 46           mov        r11,__stream
        00010a04 7e 44           add        r6,pc
        00010a06 7d 44           add        r5,pc
                             LAB_00010a08                                    XREF[1]:     00010a2a(j)
        00010a08 20 46           mov        __stream,r4
        00010a0a 4f f4 80 51     mov.w      thiz,#0x1000
        00010a0e 5a 46           mov        iArr,r11
        00010a10 ff f7 f2 ee     blx        fgets                                            char * fgets(char * __s, int __n
        00010a14 60 b1           cbz        pcVar5,LAB_00010a30
        00010a16 20 46           mov        pcVar5,r4
        00010a18 31 46           mov        thiz=>s_Xposed_0001245a,r6                       = "Xposed"
        00010a1a ff f7 f4 ee     blx        strstr                                           char * strstr(char * __haystack,
        00010a1e 28 b9           cbnz       pcVar5,LAB_00010a2c
        00010a20 20 46           mov        pcVar5,r4
        00010a22 29 46           mov        thiz=>s_frida_00012461,r5                        = "frida"
        00010a24 ff f7 ee ee     blx        strstr                                           char * strstr(char * __haystack,
        00010a28 00 28           cmp        pcVar5,#0x0
        00010a2a ed d0           beq        LAB_00010a08
                             LAB_00010a2c                                    XREF[1]:     00010a1e(j)
        00010a2c 01 24           mov        r4,#0x1
        00010a2e 00 e0           b          LAB_00010a32
                             LAB_00010a30                                    XREF[1]:     00010a14(j)
        00010a30 00 24           mov        r4,#0x0
                             LAB_00010a32                                    XREF[1]:     00010a2e(j)
        00010a32 bb f1 00 0f     cmp.w      r11,#0x0
        00010a36 1c bf           itt        ne
        00010a38 58 46           mov.ne     pcVar5,r11
        00010a3a ff f7 ea ee     blx.ne     fclose                                           int fclose(FILE * __stream)
        00010a3e f4 b9           cbnz       r4,LAB_00010a7e
        00010a40 da f8 00 00     ldr.w      pcVar5,[r10,#0x0]
        00010a44 49 46           mov        thiz,r9
        00010a46 00 22           mov        iArr,#0x0
        00010a48 00 24           mov        pos,#0x0
        00010a4a d0 f8 ec 32     ldr.w      r3,[pcVar5,#0x2ec]
        00010a4e 50 46           mov        pcVar5,r10
        00010a50 98 47           blx        r3
        00010a52 1b 49           ldr        thiz,[DAT_00010ac0]                              = 00001F98h
        00010a54 1b 4a           ldr        iArr,[DAT_00010ac4]                              = 00001E98h
        00010a56 1c 4b           ldr        r3,[DAT_00010ac8]                                = 00002032h
        00010a58 79 44           add        thiz,pc
        00010a5a 6c 31           add        thiz,#0x6c
        00010a5c 7a 44           add        iArr=>UINT_ARRAY_1,pc                            =
        00010a5e 7b 44           add        r3=>uint_array_2,pc                              =
                             Stop when counter var reaches 27 (end of iArr)
---> Entry of do-while-loop
                             LAB_00010a60                                    XREF[1]:     00010a7c(j)
        00010a60 1b 2c           cmp        pos,#0x1b
        00010a62 0e d0           beq        LAB_00010a82
        00010a64 50 f8 24 50     ldr.w      r5,[pJint_iArr_nocopy,pos,lsl #0x2]
        00010a68 52 f8 24 60     ldr.w      r6,[iArr,pos,lsl #offset UINT_ARRAY_1]           =
        00010a6c 75 40           eor        r5,r6
        00010a6e 51 f8 04 69     ldr.w      uVar7,[puVar6],#-0x4=>end_of_uint_array          = 61h    a
        00010a72 75 40           eor        r5,uVar7
        00010a74 53 f8 24 60     ldr.w      uVar7,[r3,pos,lsl #offset uint_array_2]          =
        00010a78 01 34           add        pos,#0x1
        00010a7a b5 42           cmp        r5,uVar7
---> branch condition for the `while()`, only executed as often as the loop ran
        00010a7c f0 d0           beq        LAB_00010a60
                             LAB_00010a7e                                    XREF[1]:     00010a3e(j)
        00010a7e 00 9c           ldr        pos,[sp,#0x0]=>local_1030
        00010a80 00 e0           b          LAB_00010a84
                             LAB_00010a82                                    XREF[1]:     00010a62(j)
        00010a82 4c 46           mov        pos,r9
                             LAB_00010a84                                    XREF[2]:     000109ec(j), 00010a80(j)
        00010a84 d8 f8 00 00     ldr.w      pJint_iArr_nocopy,[r8,#0x0]=>__stack_chk_guard   = ??
        00010a88 57 f8 24 1c     ldr.w      puVar6,[r7,#-0x24]
        00010a8c 40 1a           sub        pJint_iArr_nocopy,pJint_iArr_nocopy,puVar6
        00010a8e 01 bf           itttt      eq
        00010a90 20 46           mov.eq     pJint_iArr_nocopy,p_Var6
        00010a92 0d f5 80 5d     add.eq.w   sp,sp,#0x1000
        00010a96 03 b0           add.eq     sp,#0xc
        00010a98 bd e8 00 0f     pop.eq.w   { r8, r9, r10, r11 }
        00010a9c 08 bf           it         eq
        00010a9e f0 bd           pop.eq     { p_Var6, r5, uVar7, r7, pc }
        00010aa0 ff f7 bc ee     blx        __stack_chk_fail                                 undefined __stack_chk_fail()
                             -- Flow Override: CALL_RETURN (CALL_TERMINATOR)
```

- Function entry address is `0x0001099c` (`0x0001099d` for the Thumbs instruction)
- the do-while-loop is covered by the instructions from `0x00010a60 to 0x00010a7c`
- the conditional branch for the `while()` is executed at `0x00010a7c` (`0x00010a7d` for the Thumbs instruction)

So the offset from the function entry point to the instruction to trace is `runtime_function_entry_addresss + (0x00010a7d - 0x0001099d)`

In my script, this was further simplified to a staement dealing with file offsets (not memory mapping), which mathematically is the same.
Code snippet from Frida script:

```
native_checkPw = native_checkPw.add(0xa7d - 0x99d) // offset the address to the instruction we want to trace
```

# The full Frida script (targeting ARMv7a library with Android 9 libart.so present)

The Frida-agent script is written in TypeScript and thus needs `frida-compile` to translate it to pure JS.

```
/**
 *
 * Challenge Solution for Swiss Hacking Challenge 2021 - CTF Bundle 13.3.2021 - CrackMe Native
 * Author: MaMe82 (Marcus Mengs)
 *
 *
 *  */

const classWasHandled: Set<string> = new Set<string>()

function hookClassLinkerFindClass() {
  // Mangled Cpp name of libart's ClassLinker::FindClass on Android 9:
  // _ZN3art11ClassLinker9FindClassEPNS_6ThreadEPKcNS_6HandleINS_6mirror11ClassLoaderEEE
  const reClassLinkerFindClass = /art[0-9]{1,2}ClassLinker[0-9]{1,2}FindClassE/
  const mLibArt = Module.load("libart.so")
  const relevantExports = mLibArt
    .enumerateExports()
    .filter((ed) => ed.name.match(reClassLinkerFindClass))
  if (relevantExports.length <= 0) {
    console.log("ERROR: Can not hook ClassLinker::findClass")
  }

  // ToDo: findClass is more re-entrant than loadClass, hooking should be done only once
  Interceptor.attach(relevantExports[0].address, {
    onEnter(args) {
      this.name = args[2].readUtf8String()
    },
    onLeave(res) {
      if (classWasHandled.has(this.name)) return // assure class is only processed for first successful findClass

      if (res.toInt32() !== 0) {
        // if class found
        classWasHandled.add(this.name)
        // return value is of type ObjPtr<mirror::Class>, but we do not care for this, as we move back to frida-java-bridge here
        // Ref: https://android.googlesource.com/platform/art/+/master/runtime/mirror/class.h
        let tmp = (this.name as string).match(/^L(.*);$/) // ignores array classes and primitive types
        if (tmp !== null && tmp.length > 1) {
          const readableName = tmp[1].replace(/\//g, ".")

          if (readableName.startsWith("org.bfe.crackmenative")) {
            console.log(
              "!!!!!!!!!!! ClassLinker::findClass readable name:",
              readableName
            )

            onNewClassLoaded(readableName)
          }
        }
      }
    },
  })
}

function onNewClassLoaded(className: string) {
  if (className.indexOf("RootCheck") > 0) {
    // get handle to the class
    let clzRootCheck = Java.use(className)

    // always return false for RootCheck.a()
    clzRootCheck.a.implementation = function () {
      return false
    }
    // always return false for RootCheck.b()
    clzRootCheck.b.implementation = function () {
      return false
    }
    // always return false for RootCheck.c()
    clzRootCheck.c.implementation = function () {
      return false
    }
    // always return false for RootCheck.checkDebuggable()
    clzRootCheck.checkDebuggable.implementation = function () {
      return false
    }
  }

  if (className.endsWith("LoginViewModel")) hookLoginViewModel(className)
}

function bypassHookingDetection() {
  let fOpen = Module.getExportByName("libc.so", "open")

  Interceptor.attach(fOpen, {
    onEnter(args) {
      let path = args[0].readUtf8String()
      //console.log(path)
      if (path === "/proc/self/maps") {
        let newPath = Memory.allocUtf8String("/proc/self/limits") // just open 'limits' instead of 'maps' ... and there will be no Frida
        this.keepTillInvocationEnd = newPath // hack: bind allocated Memory with new string to this object (survives till invocation end)
        args[0] = newPath
      }
    },
  })
  //Interceptor.attach
}

function hookLoginViewModel(classNameLoginViewModel: string) {
  console.log("hooking: " + classNameLoginViewModel)

  let clazzLoginViewModel = Java.use(classNameLoginViewModel)

  let javaCheckPw = clazzLoginViewModel["checkPw"]

  // this variable counts how often the `while` loop of the native `checkPw` function was hit
  // it is set to 0 by the Java layer hook of `checkPw`
  // afterwards the replaced Java `checkPw` calls the legacy method multiple times with different inputs (providing input
  // arrays from Java layer is easier then doing so on native layer via JNIenv)
  // when the Java layer of the replaced checkPw counts how often the instruction corresponding to the "while loop"
  // was hit for a given input
  // If the input only changes one byte at a given position, the count should only differ for exactly one of the provided inputs
  // which allows a brute force approach
  let while_invocation_counter = 0

  javaCheckPw.implementation = function () {
    console.log("checkPw called with: " + JSON.stringify(arguments[0]))
    console.log("Replacing argument, run multi-call bruteforce instead")

    const TID = Process.enumerateThreads()[0].id // Process.getCurrentThreadId()

    // input array to play with (of length 27, as expected)
    let input = Java.array("I", Array(27).fill(0))

    let ret: any

    /** Logic to brute-force the input buffer, relying on native hook counting the hits of a probe instruction in `while_invocation_counter` variable */

    // array_pos -> input array position to test
    for (let array_pos = 0; array_pos <= 0x1b; array_pos++) {
      console.log("input: " + JSON.stringify(input))
      let max_hits = 0 // used to choose the value with most hits
      let value_at_pos = 0 // used to store the value with most hits
      for (let b = 0; b < 256; b++) {
        input[array_pos] = b
        while_invocation_counter = 0
        ret = javaCheckPw.apply(this, [input])

        // debug output
        /*
        console.log(
          "array pos, " +
            array_pos +
            ", test value: " +
            b +
            ", count of loop-end hits: " +
            while_invocation_counter
        )
        */

        if (max_hits < while_invocation_counter) {
          // update candidates
          max_hits = while_invocation_counter
          value_at_pos = b
        }
      }
      console.log(
        "input int to native checkPw at position " +
          array_pos +
          " has to be " +
          value_at_pos
      )

      // update input array
      input[array_pos] = value_at_pos
    }

    console.log(
      "Final input array to 'checkPw', which hits the while-loop most often:"
    )
    console.log("input: " + JSON.stringify(input))

    console.log(
      "last return value of checkPw, which will be passed up to the caller" +
        JSON.stringify(ret)
    )
    return ret
  }

  /** HOOK THE NATIVE 'checkPw' part at the instruction for which the execution count should be measured */

  // wait till the class loaded the native library
  while (!Process.findModuleByName("libnative-lib.so")) {}

  let nativeCheckPw = Module.getExportByName(
    "libnative-lib.so",
    "Java_org_bfe_crackmenative_ui_LoginViewModel_checkPw"
  )

  console.log("native checkPw: " + nativeCheckPw)
  // this applies to the arm_v7a version of the native library
  // native_checkPwn is at libnative-lib.so+0x99d
  // the branch which repeats the inner loop (while condition) is at libnative-lib.so+0xa7d
  // adjust the pointer offset
  nativeCheckPw = nativeCheckPw.add(0xa7d - 0x99d) // offset the address to the instruction we want to trace

  // place the actual hook (not at function entry, but at conditional branch instruction)
  Interceptor.attach(nativeCheckPw, {
    onEnter(arg) {
      //console.log("while touched")
      while_invocation_counter++ // increase the invocation counter when the instruction gets executed
    },
  })
}

hookClassLinkerFindClass()
bypassHookingDetection()

```

Script output (input string was not translated back to ASCII as described above, result is shown in the app at runtime):

```
# frida -U -l _agent.js --no-pause -f org.bfe.crackmenative
     ____
    / _  |   Frida 14.2.13 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/
Spawned `org.bfe.crackmenative`. Resuming main thread!
[SM-G900F::org.bfe.crackmenative]-> !!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.RootCheck
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginViewModelFactory
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginViewModel
hooking: org.bfe.crackmenative.ui.LoginViewModel
native checkPw: 0x8f23399d
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity$2
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity$3
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity$4
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity$5
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity$6
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginActivity
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginFormState
checkPw called with: [49,202,148,168]
Replacing argument, run multi-call bruteforce instead
input: [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 0 has to be 49
input: [49,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 1 has to be 202
input: [49,202,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 2 has to be 148
input: [49,202,148,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 3 has to be 159
input: [49,202,148,159,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 4 has to be 36
input: [49,202,148,159,36,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 5 has to be 106
input: [49,202,148,159,36,106,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 6 has to be 140
input: [49,202,148,159,36,106,140,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 7 has to be 75
input: [49,202,148,159,36,106,140,75,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 8 has to be 248
input: [49,202,148,159,36,106,140,75,248,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 9 has to be 93
input: [49,202,148,159,36,106,140,75,248,93,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 10 has to be 222
input: [49,202,148,159,36,106,140,75,248,93,222,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 11 has to be 88
input: [49,202,148,159,36,106,140,75,248,93,222,88,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 12 has to be 233
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 13 has to be 142
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,0,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 14 has to be 223
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,0,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 15 has to be 246
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,0,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 16 has to be 189
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,0,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 17 has to be 56
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,56,0,0,0,0,0,0,0,0,0]
input int to native checkPw at position 18 has to be 163
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,56,163,0,0,0,0,0,0,0,0]
input int to native checkPw at position 19 has to be 239
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,56,163,239,0,0,0,0,0,0,0]
input int to native checkPw at position 20 has to be 174
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,56,163,239,174,0,0,0,0,0,0]
input int to native checkPw at position 21 has to be 252
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,56,163,239,174,252,0,0,0,0,0]
input int to native checkPw at position 22 has to be 0
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,56,163,239,174,252,0,0,0,0,0]
input int to native checkPw at position 23 has to be 239
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,56,163,239,174,252,0,239,0,0,0]
input int to native checkPw at position 24 has to be 80
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,56,163,239,174,252,0,239,80,0,0]
input int to native checkPw at position 25 has to be 103
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,56,163,239,174,252,0,239,80,103,0]
input int to native checkPw at position 26 has to be 225
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,56,163,239,174,252,0,239,80,103,225]
input int to native checkPw at position 27 has to be 0
Final input array to 'checkPw', which hits the while-loop most often:
input: [49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,56,163,239,174,252,0,239,80,103,225]
last return value of checkPw, which will be passed up to the caller[49,202,148,159,36,106,140,75,248,93,222,88,233,142,223,246,189,56,163,239,174,252,0,239,80,103,225]
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.data.LoggedInUser
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.LoginResult
!!!!!!!!!!! ClassLinker::findClass readable name: org.bfe.crackmenative.ui.ResultActivity
```

# Script in action (non-public youtube video)

https://youtu.be/_fZ-YDYvINU
