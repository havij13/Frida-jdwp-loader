# frida-jdwp-loader

**A Python script that dynamically attaches Frida to any debuggable Android process over JDWP, enabling runtime instrumentation without root access or APK repackaging.**

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

</div>

[frida-jdwp-loader](https://github.com/frankheat/frida-jdwp-loader) is a Python script that provides a way to use Frida on non-rooted Android devices. It dynamically injects a native shared library (like frida-gadget.so) into a running application by leveraging the Java Debug Wire Protocol (JDWP).

## Inspiration and origin

The idea for this script originated from a [comment](https://www.linkedin.com/feed/update/urn:li:activity:7373729315080974336/?commentUrn=urn%3Ali%3Acomment%3A%28activity%3A7373729315080974336%2C7374082257801777153%29&dashCommentUrn=urn%3Ali%3Afsd_comment%3A%287374082257801777153%2Curn%3Ali%3Aactivity%3A7373729315080974336%29) by Frida's creator, Ole André Vadla Ravnås. He mentioned that, Frida no longer needs root access or application repackaging. Instead, it can be dynamically injected into any debuggable application's process using the Java Debug Wire Protocol (JDWP) and ADB.

This technique was expertly demonstrated by Yiannis Kozyrakis (ikoz) in his blog post, [Library injection for debuggable Android apps](https://koz.io/library-injection-for-debuggable-android-apps/). His work provided the foundational [proof-of-concept](https://github.com/ikoz/jdwp-lib-injector) for this project.

## Why a new tool?

While working with the original script, I saw opportunities to enhance its flexibility and automate the entire workflow. This project was born to address those needs, starting as a Python 3 rewrite of a fork of [jdwp-shellifier](https://github.com/hugsy/jdwp-shellifier) by hugsy and growing from there.

## Enhancements

- Modern & robust: Fully rewritten in Python 3.
- Early instrumentation: Implements an alternative to standard early instrumentation, allowing you to hook the app before its code even starts running.
- Added support for multiple frida interaction types. This allows you to change the address/port listening and run scripts in a fully autonomous manner (bypassing the INTERNET permission requirement), among other things.
- Automation:
    - Auto-Managed frida gadget: The script automatically detects the target device's architecture (ARM, ARM64, x86, x86_64) and downloads the correct version of the Frida gadget for you.
    - Multi-Device management: If you have multiple devices connected, you can easily select and switch between them.
    - Zero-Touch operation: All operations are performed programmatically. You don't need to manually enable or disable settings on the device during the injection process.
- Other small stuff.


# Background

Traditionally, using Frida on Android involves two main methods, each with significant trade-offs:

| Method | How it Works | Pros | Cons |
| --- | --- | --- | --- |
| Frida-Server | A server binary runs as root on the device, injecting into any target process. | Powerful, can attach to any process. | Requires a rooted device. |
| Frida-Gadget | The frida-gadget.so library is added to an APK, which is then re-signed and re-installed. | Works on non-rooted devices. | Requires repackaging the APK, which is complex, error-prone, and often detected by anti-tampering controls. |

[frida-jdwp-loader](https://github.com/frankheat/frida-jdwp-loader) was created to overcome these limitations, offering the benefits of the Frida-Gadget method (no root) without its biggest drawback (repackaging).

# The prerequisite

This entire process is only possible if the target application is debuggable (`android:debuggable="true"` in `AndroidManifest.xml`).

If the app is not debuggable you can:

- Run the app in an emulator that has `ro.debuggable` property set to `1`.
- Use a rooted phone so you can modify `ro.debuggable`. Normally this value is read only. However with magisk you can use `resetprop`.
- Repackage the app and set `android:debuggable="true"` in `AndroidManifest.xml`.

# Getting Started

## Requirements

- Python 3
- ADB (Android Debug Bridge) in PATH
- Android device with USB/Wireless debugging enabled

## Installation

```bash
# Clone the repository
git clone https://github.com/frankheat/frida-jdwp-loader.git
cd frida-jdwp-loader
```

### Example Usage

```bash
# Auto-download and inject frida-gadget.so
python frida-jdwp-loader.py frida -n com.example.myapplication

# Use specific frida-gadget.so version
python frida-jdwp-loader.py frida -n com.example.myapplication -g 16.1.2

# Keep the thread that hits the breakpoint suspended after spawning the app
python frida-jdwp-loader.py frida -n com.example.myapplication -s

# Spawn mode with specific activity
python frida-jdwp-loader.py frida -n com.example.myapplication -a .MainActivity

# Change listen address/port
python frida-jdwp-loader.py frida -n com.example.myapplication -i listen -L 0.0.0.0 -P 27043

# Run the script in a fully autonomous manner
python frida-jdwp-loader.py frida -n com.example.myapplication -i script -l script.js

# Inject all files from directory
python frida-jdwp-loader.py custom -n com.example.myapplication -l /path/to/lib_directory/
```

# Command line options

## frida-mode options

```
usage: frida-jdwp-loader.py frida [-h] [-g GADGET] [-i {listen,script,custom}] [-L ADDRESS] [-P PORT] [-l SCRIPT] [-f CONFIG] -n PACKAGE_NAME [-a ACTIVITY_NAME] [-m MODE] [-b JAVA_METHOD] [-p JDWP_PORT] [-nc] [-d DELAY] [-s] [-v]

options:
  -h, --help            show this help message and exit
  -g GADGET, --gadget GADGET
                        Could be one of the following:
                                Path to the frida gadget library file
                                Frida version (e.g., '16.6.6')
                                auto, to automatically detect (Default)
  -i {listen,script,custom}, --interaction {listen,script,custom}
                        Interaction mode (Default: listen)
  -L ADDRESS, --listen ADDRESS
                        Listen on ADDRESS (used with --interaction listener)
                        (Default: 127.0.0.1)
  -P PORT, --frida-port PORT
                        Listen on PORT (used with --interaction listener)
                        (Default: 27042)
  -l SCRIPT, --load SCRIPT
                        load SCRIPT (Required with --interaction script)
  -f CONFIG, --config-file CONFIG
                        load CONFIG-FILE (Required with --interaction custom)
  -n PACKAGE_NAME, --package PACKAGE_NAME
                        Target Android package name (e.g., com.example.app)
  -a ACTIVITY_NAME, --activity ACTIVITY_NAME
                        Target activity name (Default: launcher activity)
  -m MODE, --mode MODE  Select mode:
                                spawn (Default)
                                attach
  -b JAVA_METHOD, --break-on JAVA_METHOD
                        Java method to break on for injection (full path required)
                        Default depends on mode:
                                spawn -> android.app.Application.onCreate
                                attach -> android.app.Activity.onStart
  -p JDWP_PORT, --port JDWP_PORT
                        Local port number for JDWP forwarding (Default: 8715)
  -nc, --no-clear       Don't clear after injection
  -d DELAY, --delay DELAY
                        Delay between operations (Default: 2)
  -s, -suspended        Keep the thread that hits the breakpoint suspended after spawning the app
  -k, --keep-files      Keep uploaded files after execution (default: files are removed)
  -v, --verbose         Enable verbose logging output
```

## custom-mode options

```
usage: frida-jdwp-loader.py custom [-h] -l LIB_PATH -n PACKAGE_NAME [-a ACTIVITY_NAME] [-m MODE] [-b JAVA_METHOD] [-p JDWP_PORT] [-nc] [-d DELAY] [-s] [-v]

options:
  -h, --help            show this help message and exit
  -l LIB_PATH, --lib-path LIB_PATH
                        Path to the custom library file/directory to inject
  -n PACKAGE_NAME, --package PACKAGE_NAME
                        Target Android package name (e.g., com.example.app)
  -a ACTIVITY_NAME, --activity ACTIVITY_NAME
                        Target activity name (Default: launcher activity)
  -m MODE, --mode MODE  Select mode:
                                spawn (Default)
                                attach
  -b JAVA_METHOD, --break-on JAVA_METHOD
                        Java method to break on for injection (full path required)
                        Default depends on mode:
                                spawn -> android.app.Application.onCreate
                                attach -> android.app.Activity.onStart
  -p JDWP_PORT, --port JDWP_PORT
                        Local port number for JDWP forwarding (Default: 8715)
  -nc, --no-clear       Don't clear after injection
  -d DELAY, --delay DELAY
                        Delay between operations (Default: 2)
  -s, -suspended        Keep the thread that hits the breakpoint suspended after spawning the app
  -k, --keep-files      Keep uploaded files after execution (default: files are removed)
  -v, --verbose         Enable verbose logging output
```

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# Acknowledgments

- [ikoz](https://github.com/ikoz) - [jdwp-lib-injector](https://github.com/ikoz/jdwp-lib-injector), [Library injection for debuggable Android apps](https://koz.io/library-injection-for-debuggable-android-apps/)
- [hugsy](https://github.com/hugsy) - [jdwp-shellifier](https://github.com/hugsy/jdwp-shellifier)
- [oleavr](https://github.com/oleavr) - [Frida](https://frida.re/)