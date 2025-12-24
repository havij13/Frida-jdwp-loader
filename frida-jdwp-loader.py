import json
import logging
import lzma
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import struct
import argparse
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from urllib.request import urlopen

# Default behavior for injection logic
BREAK_ON_SPAWN_DEFAULT = "android.app.Application.onCreate"
BREAK_ON_ATTACH_DEFAULT = "android.app.Activity.onStart"

# Paths and names used during file operations on the device
REMOTE_TEMP_PATH = "/data/local/tmp"
INJECTION_DIR_NAME = "this_is_fine"

# ADB and device interaction settings
DEFAULT_JDWP_PORT = 8715
ADB_COMMAND_TIMEOUT = 30
APP_START_MAX_ATTEMPTS = 10
APP_START_RETRY_DELAY_SEC = 1

# Frida Gadget and network settings
FRIDA_GADGET_URL_TEMPLATE = "https://github.com/frida/frida/releases/download/{version}/frida-gadget-{version}-android-{abi}.so.xz"
DEFAULT_FRIDA_LISTEN_ADDRESS = "127.0.0.1"
DEFAULT_FRIDA_PORT = 27042
DOWNLOAD_TIMEOUT_SEC = 60
DOWNLOAD_CHUNK_SIZE_BYTES = 8192

# Delay
DELAY = 2

class JDWPClient:
    """Manages JDWP operation."""

    # Not all methods are used, but they could be really useful for debugging.

    # JDWP protocol variables
    HANDSHAKE = b"JDWP-Handshake"

    # Command signatures
    VERSION_SIG = (1, 1)
    CLASSESBYSIGNATURE_SIG = (1, 2)
    ALLCLASSES_SIG = (1, 3)
    ALLTHREADS_SIG = (1, 4)
    IDSIZES_SIG = (1, 7)
    CREATESTRING_SIG = (1, 11)
    SUSPENDVM_SIG = (1, 8)
    RESUMEVM_SIG = (1, 9)
    SIGNATURE_SIG = (2, 1)
    FIELDS_SIG = (2, 4)
    METHODS_SIG = (2, 5)
    GETVALUES_SIG = (2, 6)
    CLASSOBJECT_SIG = (2, 11)
    INVOKESTATICMETHOD_SIG = (3, 3)
    REFERENCETYPE_SIG = (9, 1)
    INVOKEMETHOD_SIG = (9, 6)
    STRINGVALUE_SIG = (10, 1)
    THREADNAME_SIG = (11, 1)
    THREADSUSPEND_SIG = (11, 2)
    THREADRESUME_SIG = (11, 3)
    THREADSTATUS_SIG = (11, 4)
    EVENTSET_SIG = (15, 1)
    EVENTCLEAR_SIG = (15, 2)
    EVENTCLEARALL_SIG = (15, 3)

    # Other codes
    MODKIND_COUNT = 1
    MODKIND_THREADONLY = 2
    MODKIND_CLASSMATCH = 5
    MODKIND_LOCATIONONLY = 7
    EVENT_BREAKPOINT = 2
    SUSPEND_EVENTTHREAD = 1
    SUSPEND_ALL = 2
    NOT_IMPLEMENTED = 99
    VM_DEAD = 112
    TAG_OBJECT = 76
    TAG_STRING = 115
    TYPE_CLASS = 1

    INVOKE_DEFAULT = 0
    INVOKE_SINGLE_THREADED = 1


    def __init__(self, host: str, port: int = 8000):
        """
        Initialize a JDWP (Java Debug Wire Protocol) client that connects to a specified host and port.

        Args:
            host (str): The hostname or IP address of the JDWP server to connect to.
            port (int, optional): The port number of the JDWP server. Defaults to 8000.
        """
        self._host = host
        self._port = port
        self._id = 0x01

        self._socket = None

        self.logger = logging.getLogger(__name__)
    
    # Pubic methods

    def set_breakpoint(self, break_on_class: str, break_on_method: str, suspendPolicy: int) -> int:
        """Sets a breakpoint at a specific method in the debugged JVM.

        Args:
            break_on_class (str): Fully qualified class name where the breakpoint should be set.
            break_on_method (str): Name of the method to break on.
            suspendPolicy (int): Suspend policy when breakpoint is hit. Determines 
                            which threads are suspended.

        Returns:
            int: Request ID of the created breakpoint event, or -1 if the class
                or method could not be found.
        """
        c = self._get_class_by_name(break_on_class)
        if c is None:
            raise Exception(f"Could not access class '{break_on_class}'. It is possible that this class is not used by application.")

        m = self._get_method_by_name(refTypeId=c["refTypeId"], name=break_on_method)
        if m is None:
            raise Exception(f"Could not access method '{break_on_method}'")

        loc = bytes([JDWPClient.TYPE_CLASS])
        loc += self._format(self.referenceTypeIDSize, c["refTypeId"])
        loc += self._format(self.methodIDSize, m["methodId"])
        loc += struct.pack(">II", 0, 0)
        data = [
            (JDWPClient.MODKIND_LOCATIONONLY, loc),
        ]
        rId = self._send_event(
            JDWPClient.EVENT_BREAKPOINT,
            suspendPolicy,
            *data
        )
        self.logger.debug(f"Created break event id={rId:#x}")
        return rId
    
    def run(self, resume: bool, clear_breakpoint: bool, rId: int) -> int:
        """Runs the debugged JVM until a breakpoint is hit.

        Args:
            resume (bool): If True, resumes the VM before waiting for the breakpoint.
                        Set to True if the VM is currently suspended.
            clear_breakpoint (bool): If True, removes the breakpoint event after it
                                is hit. Set to False if you want to keep the
                                breakpoint active for future hits.
            rId (int): Request ID of the breakpoint event to wait for. This should
                  be the ID returned from set_breakpoint().

        Returns:
            int: Thread ID of the thread that hit the breakpoint.
        """
        if resume:
            self._resume_vm()

        self.logger.info(f"Waiting for the breakpoint ")
        while True:
            ret = self._parse_event_breakpoint(buf=self._wait_for_event(), event_id=rId)
            if ret is not None:
                rId, tId, loc = ret
                self.logger.debug(f"Received matching event from thread {tId:#x}")
                break

        if clear_breakpoint:
            self._clear_event(JDWPClient.EVENT_BREAKPOINT, rId)
        
        return tId
    
    def exec_payload(self, command: str, threadId: int):
        """Invokes a command on the JVM target using the JDWP protocol. 
        This command will execute with JVM privileges.

        Args:
            command (str): The command string to execute on the JVM.
            threadId (int): The thread in which to invoke.

        Raises:
            Exception: If any JDWP operation fails or the expected response is not received.
        """
        self.logger.debug(f"Payload to send: '{command}'")
        command = command.encode(encoding="utf-8")

        # 1. get Runtime class reference
        runtimeClass = self._get_class_by_name("Ljava/lang/Runtime;")
        if runtimeClass is None:
            raise Exception("Cannot find class Runtime")
        self.logger.debug(f"Found Runtime class: id={runtimeClass['refTypeId']:#x}")

        # 2. get getRuntime() meth reference
        getRuntimeMeth = self._get_method_by_name(refTypeId=runtimeClass["refTypeId"], name="getRuntime")
        if getRuntimeMeth is None:
            raise Exception("Cannot find method Runtime.getRuntime()")
        self.logger.debug(f"Found Runtime.getRuntime(): id={getRuntimeMeth['methodId']:#x}")

        # 3. Allocate string containing our command to exec()
        cmd_obj_id = self._create_string(command)
        if not cmd_obj_id:
            raise Exception("Failed to allocate command string on target JVM")
        self.logger.debug(f"Command string object created id:{cmd_obj_id:x}")

        # 4. Use context to get Runtime object
        buf = self._invoke_static(runtimeClass["refTypeId"], threadId, getRuntimeMeth["methodId"], self.INVOKE_SINGLE_THREADED)
        if buf[0] != JDWPClient.TAG_OBJECT:
            raise Exception(
                "Unexpected return type from _invoke_static: expected Object"
            )
        rt = self._unformat(self.objectIDSize, buf[1 : 1 + self.objectIDSize])
        if rt is None:
            raise Exception("Failed to _invoke Runtime.getRuntime() method")
        self.logger.debug(f"Runtime.getRuntime() returned context id:{rt:#x}")

        # 5. Find exec() method
        exec_meth = self._get_method_by_name(refTypeId=runtimeClass["refTypeId"], name="exec")
        if exec_meth is None:
            raise Exception("Runtime.exec() method not found")
        self.logger.debug(f"Found Runtime.exec(): id={exec_meth['methodId']:x}")

        # 6. Call exec() in this context with the allocated string
        data = [
            struct.pack(">B", JDWPClient.TAG_OBJECT) + self._format(self.objectIDSize, cmd_obj_id)
        ]
        buf = self._invoke(
            rt, threadId, runtimeClass["refTypeId"], exec_meth["methodId"], self.INVOKE_SINGLE_THREADED, *data
        )
        if buf[0] != JDWPClient.TAG_OBJECT:
            raise Exception(
                "Unexpected return type from Runtime.exec(): expected Object"
            )

        ret_id = self._unformat(self.objectIDSize, buf[1 : 1 + self.objectIDSize])
        self.logger.debug(f"Runtime.exec() successful, retId={ret_id:x}")
    
    def load_library(self, library: str, threadId: int):
        """Load a library on the JVM target using the JDWP protocol.
        The loading will execute with JVM privileges.

        Args:
            library (str): The path of the library to loaded.
            threadId (int): The thread in which to invoke.

        Raises:
            Exception: If any JDWP operation fails or the expected response is not received.
        """
        self.logger.info(f"Library to load: '{library}'")
        library = library.encode(encoding="utf-8")

        # 1. get Runtime class reference
        runtimeClass = self._get_class_by_name("Ljava/lang/Runtime;")
        if runtimeClass is None:
            raise Exception("Cannot find class Runtime")
        self.logger.debug(f"Found Runtime class: id={runtimeClass['refTypeId']:#x}")

        # 2. get getRuntime() meth reference
        getRuntimeMeth = self._get_method_by_name(refTypeId=runtimeClass["refTypeId"], name="getRuntime")
        if getRuntimeMeth is None:
            raise Exception("Cannot find method Runtime.getRuntime()")
        self.logger.debug(f"Found Runtime.getRuntime(): id={getRuntimeMeth['methodId']:#x}")

        # 3. Allocate string containing our command to load()
        cmd_obj_id = self._create_string(library)
        if not cmd_obj_id:
            raise Exception("Failed to allocate command string on target JVM")
        self.logger.debug(f"Command string object created id:{cmd_obj_id:x}")

        # 4. Use context to get Runtime object
        buf = self._invoke_static(runtimeClass["refTypeId"], threadId, getRuntimeMeth["methodId"], self.INVOKE_SINGLE_THREADED)
        if buf[0] != JDWPClient.TAG_OBJECT:
            raise Exception(
                "Unexpected return type from _invoke_static: expected Object"
            )
        rt = self._unformat(self.objectIDSize, buf[1 : 1 + self.objectIDSize])
        if rt is None:
            raise Exception("Failed to _invoke Runtime.getRuntime() method")
        self.logger.debug(f"Runtime.getRuntime() returned context id:{rt:#x}")

        # 5. Find load() method
        load_meth = self._get_method_by_name(refTypeId=runtimeClass["refTypeId"], name="load")
        if load_meth is None:
            raise Exception("Runtime.load() method not found")
        self.logger.debug(f"Found Runtime.load(): id={load_meth['methodId']:x}")

        # 6. Call load() in this context with the allocated string
        data = [
            struct.pack(">B", JDWPClient.TAG_OBJECT) + self._format(self.objectIDSize, cmd_obj_id)
        ]
        self._invoke(
            rt, threadId, runtimeClass["refTypeId"], load_meth["methodId"], self.INVOKE_SINGLE_THREADED, *data
        )
        self.logger.debug(f"Runtime.load() successful")


    # Dunders

    def __repr__(self):
        return f"JDWPClient(host='{self._host}', port={self._port})"

    def __str__(self):
        return f"JDWPClient connected to {self._host}:{self._port}"

    def __enter__(self):
        self._handshake(self._host, self._port)
        self._suspend_vm()
        self._get_id_sizes()
        self._get_version()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._socket:
            self._socket.close()
            self._socket = None

    
    # Private methods

    def _create_packet(self, cmdsig, data=b"") -> bytes:
        """
        Create a JDWP packet with the specified command signature and data.

        Args:
            cmdsig (tuple): A tuple containing the command set and the command within that set.
            data (bytes, optional): The data to be included in the packet. Defaults to an empty bytes object.

        Returns:
            bytes: A binary string representing the constructed JDWP packet.
        """
        flags = 0x00
        cmdset, cmd = cmdsig
        pktlen = len(data) + 11
        pkt = struct.pack(">IIBBB", pktlen, self._id, flags, cmdset, cmd)
        pkt += data
        self._id += 2
        return pkt

    def _read_reply(self) -> bytes:
        """
        Reads a reply from the JDWP server and returns the packet data.

        Raises:
            Exception: If an error code is received in the reply packet.

        Returns:
            bytes: The raw packet data received from the server.
        """
        header = self._socket.recv(11)
        if len(header) < 11:
            raise Exception("Incomplete reply header")
        pktlen, id, flags, errcode = struct.unpack(">IIcH", header)
        if flags == b"\x80":  # b'\x80' is the flag for a reply packet
            if errcode != 0:
                raise Exception(f"Received error code {errcode}")

        buf = b""
        while len(buf) + 11 < pktlen:
            data = self._socket.recv(1024)
            if data:
                buf += data
            else:
                # If no data is received, we wait a bit before trying again
                time.sleep(1)

        return buf

    def _parse_entries(self, buf: bytes, formats: list, explicit: bool = True) -> list:
        """
        Parses entries from a buffer according to the given format specifiers.
        Supports explicit count of entries or assumes a single entry if not explicit.

        Args:
            buf (bytes): The buffer containing the data to parse.
            formats (list): A list of tuples where each tuple contains the format
                            specifier and the corresponding name of the field.
            explicit (bool): If True, expects the number of entries as the first
                            4 bytes of the buffer. Defaults to True.

        Returns:
            list: A list of dictionaries, each representing a parsed entry.
        """
        entries = []
        index = 0

        if explicit:
            (nb_entries,) = struct.unpack(">I", buf[:4])
            buf = buf[4:]
        else:
            nb_entries = 1

        for i in range(nb_entries):
            data = {}
            for fmt, name in formats:
                if fmt == "L" or fmt == 8:
                    (data[name],) = struct.unpack(">Q", buf[index : index + 8])
                    index += 8
                elif fmt == "I" or fmt == 4:
                    (data[name],) = struct.unpack(">I", buf[index : index + 4])
                    index += 4
                elif fmt == "S":
                    (str_len,) = struct.unpack(">I", buf[index : index + 4])
                    data[name] = buf[index + 4 : index + 4 + str_len].decode("utf-8")
                    index += 4 + str_len
                elif fmt == "C":
                    (data[name],) = struct.unpack(">c", buf[index : index + 1])
                    index += 1
                elif fmt == "Z":
                    # Assuming this is a custom format and `_solve_string` is a method defined elsewhere.
                    (t,) = struct.unpack(">c", buf[index : index + 1])
                    index += 1
                    if t == b"s":
                        data[name] = self._solve_string(buf[index : index + 8])
                        index += 8
                    elif t == b"I":
                        (data[name],) = struct.unpack(">I", buf[index : index + 4])
                        index += 4
                else:
                    self.logger.error(f"Error: Unknown format {fmt}")
                    sys.exit(1)
            entries.append(data)

        return entries

    def _format(self, fmt: str | int, value) -> bytes:
        """Packs and converts an object.

        It supports packing 64-bit and 32-bit unsigned integers.

        Args:
            fmt (str | int): The format character ('L' for 64-bit or 'I' for 32-bit unsigned integer)
                              or the size of the data to be unpacked (8 for 64-bit, 4 for 32-bit).
            value: The object to be packed.

        Raises:
            Exception: If the format is unknown or unsupported.

        Returns:
            bytes: The packed object.
        """
        if fmt == "L" or fmt == 8:
            a = struct.pack(">Q", value)
            return struct.pack(">Q", value)

        if fmt == "I" or fmt == 4:
            return struct.pack(">I", value)

        raise Exception("Unknown format")

    def _unformat(self, fmt: str | int, value) -> int:
        """
        Unpacks and converts a bytes object to a Python data type based on the given format.

        This method is used to convert bytes received from the server into a usable Python data type.
        It supports unpacking 64-bit and 32-bit unsigned integers.

        Args:
            fmt (str or int): The format character ('L' for 64-bit or 'I' for 32-bit unsigned integer)
                              or the size of the data to be unpacked (8 for 64-bit, 4 for 32-bit).
            value: The object to be unpacked.

        Returns:
            int: The unpacked integer.

        Raises:
            ValueError: If the input bytes object does not contain enough bytes for the specified format.
            Exception: If the format is unknown or unsupported.
        """
        try:
            if fmt in ("L", 8):
                # Unpack a 64-bit unsigned integer from the beginning of the byte sequence.
                return struct.unpack(">Q", value[:8])[0]
            elif fmt in ("I", 4):
                # Unpack a 32-bit unsigned integer from the beginning of the byte sequence.
                return struct.unpack(">I", value[:4])[0]
            else:
                raise Exception(f"Unknown format: {fmt}")
        except struct.error as e:
            raise ValueError(f"Insufficient bytes for format '{fmt}': {e}")

    def _handshake(self, host: str, port: int):
        """
        Establish a handshake with the JDWP server specified by the host and port.

        This method initiates a socket connection to the server and sends a handshake
        message. It then waits for a handshake response to confirm successful communication.

        Args:
            host (str): The hostname or IP address of the JDWP server to connect to.
            port (int): The port number on which the JDWP server is listening.

        Raises:
            Exception: If the socket connection fails.
            Exception: If the handshake is not successful.
        """
        self.logger.info(f"Target: {host}:{port}")
        current_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.logger.info("Trying to connect...")
            current_socket.connect((host, port))
        except socket.error as msg:
            raise Exception(f"Failed to connect: {msg}")
        else:
            self.logger.info("Connection successful!")

        current_socket.send(JDWPClient.HANDSHAKE)
        self.logger.debug("Handshake sent")

        received_handshake = current_socket.recv(len(JDWPClient.HANDSHAKE))

        if received_handshake != JDWPClient.HANDSHAKE:
            current_socket.close()
            raise Exception("Failed to handshake with the server.")

        self._socket = current_socket
        self.logger.debug("Handshake successful")

    
    # VirtualMachine Command Set (1)

    def _get_version(self):
        """
        Requests the JDWP and VM version information from the server.

        This method sends a packet with the version signature to the server,
        then reads the reply and sets the corresponding attributes on the client
        with the server's JDWP protocol version and VM version details.
        """
        self.logger.debug("Requesting version information from the JDWP server...")
        self._socket.sendall(self._create_packet(JDWPClient.VERSION_SIG))
        buf = self._read_reply()
        formats = [
            ("S", "description"),
            ("I", "jdwpMajor"),
            ("I", "jdwpMinor"),
            ("S", "vmVersion"),
            ("S", "vmName"),
        ]
        for entry in self._parse_entries(buf, formats, False):
            for name, value in entry.items():
                setattr(self, name, value)
                self.logger.debug(f"{name}: {value}")

        self.logger.debug("Version information has been successfully received and set.")

    def _get_loaded_classes(self) -> list:
        """
        Retrieves a list of all classes currently loaded by the JVM.

        This method sends a command to request all classes from the JVM and parses the response.

        Returns:
            list: A list of dictionaries, each containing details of a class such as type tag, type ID,
                  signature, and status.
        """
        self._socket.sendall(self._create_packet(JDWPClient.ALLCLASSES_SIG))
        buf = self._read_reply()
        formats = [
            ("C", "refTypeTag"),
            (self.referenceTypeIDSize, "refTypeId"),
            ("S", "signature"),
            ("I", "status"),
        ]
        classes = self._parse_entries(buf, formats)
        return classes
    
    def _get_class_by_name(self, name: str) -> dict | None:
        """Find a class by its name.

        Args:
            name (str): The name of the class to search for.

        Returns:
            dict | None: A dictionary containing class information if found, or None if not found.
        """
        classes = self._get_loaded_classes()
        for entry in classes:
            if entry["signature"].lower() == name.lower():
                return entry
        return None

    def _all_threads(self, include_names: bool = False) -> list:
        """Retrieve information about all threads from the JDWP server.

        Args:
            include_names (bool): Return thread IDs and names, otherwise, only thread IDs.

        Returns:
            list: A list of dictionaries containing thread information.
        """
        self._socket.sendall(self._create_packet(self.ALLTHREADS_SIG))
        buf = self._read_reply()
        formats = [(self.objectIDSize, "threadId")]
        threads = self._parse_entries(buf, formats)

        if include_names:
            threadsNames = []
            for t in threads:
                threadId = self._format(self.objectIDSize, t["threadId"])
                self._socket.sendall(self._create_packet(self.THREADNAME_SIG, data=threadId))
                buf = self._read_reply()
                threadsNames.append(
                    {"name": self._read_string(buf).decode("utf-8"),
                    "threadId":t['threadId']
                    }
                )

            return threadsNames
        
        return threads
    
    # Not used
    def _get_thread_by_name(self, name: str) -> dict | None:
        """Find a thread by its name.

        Args:
            name (str): The name of the thread to search for.

        Returns:
            dict | None: A dictionary containing thread information if found, or None if not found.
        """
        threads = self._all_threads()
        for t in threads:
            threadId = self._format(self.objectIDSize, t["threadId"])
            self._socket.sendall(self._create_packet(self.THREADNAME_SIG, data=threadId))
            buf = self._read_reply()
            if len(buf) and name == self._read_string(buf).decode("utf-8"):
                return t
        return None
    
    def _get_thread_by_id(self, id: int) -> str | None:
        """Find a thread by its id.

        Args:
            id (int): The name of the thread to search for.

        Returns:
            str | None:  A dictionary containing thread information if found, or None if not found.
        """
        threads = self._all_threads()
        for t in threads:
            threadId = self._format(self.objectIDSize, t["threadId"])
            self._socket.sendall(self._create_packet(self.THREADNAME_SIG, data=threadId))
            buf = self._read_reply()
            if t['threadId'] == id:
                name = self._read_string(buf).decode("utf-8")
                return name
        return None

    def _get_id_sizes(self):
        """Requests the sizes of various ID types from the JDWP server.

        This method sends a packet with the ID sizes signature to the server,
        then reads the reply and sets the corresponding attributes on the client.
        """
        self.logger.debug("Requesting ID sizes from the JDWP server...")
        self._socket.sendall(self._create_packet(JDWPClient.IDSIZES_SIG))
        buf = self._read_reply()
        formats = [
            ("I", "fieldIDSize"),
            ("I", "methodIDSize"),
            ("I", "objectIDSize"),
            ("I", "referenceTypeIDSize"),
            ("I", "frameIDSize"),
        ]
        for entry in self._parse_entries(buf, formats, False):
            for name, value in entry.items():
                setattr(self, name, value)
                self.logger.debug(f"{name}: {value}")

        self.logger.debug("ID sizes have been successfully received and set.")

    def _suspend_vm(self):
        """
        Suspends the execution of the application running in the target VM. 
        All Java threads currently running will be suspended.
        """
        self._socket.sendall(self._create_packet(self.SUSPENDVM_SIG))
        self.logger.debug("Suspend VM signal sent")
        self._read_reply()
    
    def _resume_vm(self):
        """
        Resumes execution of the application after the suspend command 
        or an event has stopped it.
        """
        self._socket.sendall(self._create_packet(JDWPClient.RESUMEVM_SIG))
        self.logger.debug("Resume VM signal sent")
        self._read_reply()

    def _create_string(self, data: bytes) -> int:
        """Creates a new string object

        Args:
            data (bytes): UTF-8 characters to use in the created string.

        Returns:
            int: Created string ID
        """
        buf = self._build_string(data)
        self._socket.sendall(self._create_packet(JDWPClient.CREATESTRING_SIG, data=buf))
        buf = self._read_reply()
        stringId = self._parse_entries(buf, [(self.objectIDSize, "objId")], False)
        return stringId[0]['objId']

    def _build_string(self, data: bytes) -> bytes:
        """Builds a binary buffer for a JDWP string packet.

        Args:
            data (bytes): UTF-8 encoded string data to be packed.

        Returns:
            bytes: Binary buffer with format: [4-byte length][string data]
        """
        return struct.pack(">I", len(data)) + data

    
    # ReferenceType Command Set (2)
    
    def _get_methods(self, refTypeId: int) -> list:
        """Retrieve methods associated with a reference type.

        Args:
            refTypeId (int): The class reference type ID for which to retrieve methods.

        Returns:
            list: A list of dictionaries containing method information.
        """
        refId = self._format(self.referenceTypeIDSize, refTypeId)
        self._socket.sendall(self._create_packet(JDWPClient.METHODS_SIG, data=refId))
        buf = self._read_reply()
        formats = [
            (self.methodIDSize, "methodId"),
            ("S", "name"),
            ("S", "signature"),
            ("I", "modBits"),
        ]
        methods = self._parse_entries(buf, formats)
        return methods

    def _get_method_by_name(self, refTypeId: int, name: str) -> dict | None:
        """Find a method by its name.

        Args:
            refTypeId (int): The class reference type ID for which to retrieve methods.
            name (str): The name of the method to search for.

        Returns:
            dict | None: Dictionary containing method information or None if not found
        """
        methods = self._get_methods(refTypeId=refTypeId)
        for entry in methods:
            if entry["name"].lower() == name.lower():
                return entry
        return None

    # Not used
    def _get_fields(self, refTypeId) -> list:
        """Returns information for each field in a reference type.

        Args:
            refTypeId: The reference type ID.

        Returns:
            list: A list of dictionaries containing field information.
        """
        refId = self._format(self.referenceTypeIDSize, refTypeId)
        self._socket.sendall(self._create_packet(self.FIELDS_SIG, data=refId))
        buf = self._read_reply()
        formats = [
            (self.fieldIDSize, "fieldId"),
            ("S", "name"),
            ("S", "signature"),
            ("I", "modbits"),
        ]
        fields = self._parse_entries(buf, formats)
        return fields
 
    # Not used
    def _get_value(self, refTypeId, fieldId):
        """Returns the value of one or more static fields of the reference type.

        Args:
            refTypeId: The reference type ID. 
            fieldId: A field to get.

        Returns:
            Any: The field value.
        """
        data = self._format(self.referenceTypeIDSize, refTypeId)
        data += struct.pack(">I", 1)
        data += self._format(self.fieldIDSize, fieldId)
        self._socket.sendall(self._create_packet(self.GETVALUES_SIG, data=data))
        buf = self._read_reply()
        formats = [("Z", "value")]
        field = self._parse_entries(buf, formats)[0]
        return field

    
    # ClassType Command Set (3)
    
    def _invoke_static(self, classId, threadId, methId, invokeOption, *args) -> bytes:
        """Invokes a static method.

        Args:
            classId: The class type ID.
            threadId: The thread in which to invoke.
            methId: The method to invoke.
            invokeOption: Invocation options.
            *args: Variable number of arguments to pass to the invoked method.

        Returns:
            bytes: The raw packet data received from the server.
        """
        data = self._format(self.referenceTypeIDSize, classId)
        data += self._format(self.objectIDSize, threadId)
        data += self._format(self.methodIDSize, methId)
        data += struct.pack(">I", len(args))
        for arg in args:
            data += arg
        data += struct.pack(">I", invokeOption)

        self._socket.sendall(self._create_packet(JDWPClient.INVOKESTATICMETHOD_SIG, data=data))
        buf = self._read_reply()
        return buf
    
    
    # ObjectReference Command Set (9)

    def _invoke(self, objId, threadId, classId, methId, invokeOption, *args) -> bytes:
        """Invokes a instance method.

        Args:
            objId: The object ID.
            threadId: The thread in which to invoke.
            classId: The class type.
            methId: The method to invoke.
            invokeOption: Invocation options.
            *args: Variable number of arguments to pass to the invoked method.

        Returns:
            bytes: The raw packet data received from the server.
        """
        data = self._format(self.objectIDSize, objId)
        data += self._format(self.objectIDSize, threadId)
        data += self._format(self.referenceTypeIDSize, classId)
        data += self._format(self.methodIDSize, methId)
        data += struct.pack(">I", len(args))
        for arg in args:
            data += arg
        data += struct.pack(">I", invokeOption)

        self._socket.sendall(self._create_packet(JDWPClient.INVOKEMETHOD_SIG, data=data))
        buf = self._read_reply()
        return buf

    
    # StringReference Command Set (10)

    def _solve_string(self, objId) -> bytes | None:
        """Returns the characters contained in the string.

        Args:
            objId: The String object ID.

        Returns:
            bytes | None:  The UTF-8 representation of the string's contents, 
                           or None if the reply was empty.
        """
        self._socket.sendall(self._create_packet(JDWPClient.STRINGVALUE_SIG, data=objId))
        buf = self._read_reply()
        if len(buf):
            return self._read_string(buf)

        return None
    
    def _read_string(self, data: bytes) -> bytes:
        """Parse a JDWP 'STRING' value from a reply buffer.

        Args:
            data (bytes): The raw bytes returned by the JVM.

        Returns:
            bytes: The UTF-8 bytes that make up the Java string.
        """
        size = struct.unpack(">I", data[:4])[0]
        return data[4 : 4 + size]


    # ThreadReference Command Set (11)

    # Not used
    def _query_thread(self, threadId, kind) -> bytes:
        """Sends thread query to JDWP server.

        Args:
            threadId: The thread object ID.
            kind: Command signature.

        Returns:
            bytes: The raw packet data received from the server.
        """
        data = self._format(self.objectIDSize, threadId)
        self._socket.sendall(self._create_packet(kind, data=data))
        return self._read_reply()

    # Not used
    def _suspend_thread(self, threadId):
        """Suspends the thread.

        Args:
            threadId: The thread object ID.
        """
        self._query_thread(threadId, self.THREADSUSPEND_SIG)

    # Not used
    def _status_thread(self, threadId) -> tuple[int, int]:
        """Returns the current status of a thread.

        Args:
            threadId: The thread object ID.

        Returns:
            tuple[int, int]: A tuple containing the threadStatus and the suspendStatus.
        """
        buf = self._query_thread(threadId, self.THREADSTATUS_SIG)
        formats = [
            ("I", "threadStatus"),
            ("I", "suspendStatus")
        ]
        reply = self._parse_entries(buf, formats, explicit=False)
        threadStatus = reply[0]['threadStatus']
        suspendStatus = reply[0]['suspendStatus']
        return threadStatus, suspendStatus

    # Not used
    def _resume_thread(self, threadId):
        """Resumes the execution of a given thread.

        Args:
            threadId: The thread object ID.
        """
        self._query_thread(threadId, self.THREADRESUME_SIG)
    
    
    # EventRequest Command Set (15)

    def _send_event(self, event_code, suspendPolicy, *args) -> int:
        """Sends an event to the JDWP server.

        Args:
            event_code (int): The event code corresponding to the event to be sent.
            suspendPolicy: SuspendPolicy constant.
            *args: Variable length argument list representing the event arguments.

        Returns:
            int: The request ID from the event sent.
        """
        data = bytes([event_code, suspendPolicy]) + struct.pack(">I", len(args))
        for kind, option in args:
            data += bytes([kind]) + option
        self._socket.sendall(self._create_packet(self.EVENTSET_SIG, data=data))
        buf = self._read_reply()
        return struct.unpack(">I", buf)[0]

    def _clear_event(self, event_code: int, request_id: int):
        """Clears a set event from the JDWP server.

        Args:
            event_code (int): The event code corresponding to the event to be cleared.
            request_id (int): The request ID of the event to clear.
        """
        data = bytes([event_code]) + struct.pack(">I", request_id)
        self._socket.sendall(self._create_packet(JDWPClient.EVENTCLEAR_SIG, data=data))
        self._read_reply()

    def _wait_for_event(self) -> bytes:
        """Waits and reads the next event from the JDWP server.

        Returns:
            bytes: The raw event data received.
        """
        buf = self._read_reply()
        return buf

    def _parse_event_breakpoint(self, buf: bytes, event_id: int) -> tuple[int, int, int] | None:
        """Parses a breakpoint event received from the JDWP server.

        Args:
            buf (bytes): The buffer containing the event data.
            event_id (int): The ID of the event to parse.

        Returns:
            tuple[int, int, int] | None:  A tuple containing the request ID, thread ID, 
                and location (-1 since it's not used) if the event IDs match.
        """
        received_id = struct.unpack(">I", buf[6:10])[0]
        if received_id != event_id:
            return None
        thread_id = self._unformat(self.objectIDSize, buf[10 : 10 + self.objectIDSize])
        location = -1  # not used in this context
        return received_id, thread_id, location


class AndroidDeviceManager:
    """Manages Android device connections and operations."""
    
    def __init__(
        self,
        package_name: str = None,
        activity_name: str = None,
        jdwp_port: int = DEFAULT_JDWP_PORT
    ):
        """Initialize the Android device manager.

        Args:
            package_name (str, optional): Target Android package name. Defaults to None.
            activity_name (str, optional): Target activity name. Defaults to None.
            jdwp_port (int, optional): Local port for JDWP forwarding. Defaults to 8715.

        Raises:
            RuntimeError: If device selection fails.
            ValueError: If package name is invalid.
        """
        self.logger = logging.getLogger(__name__)

        self.jdwp_port = jdwp_port
        self.debugging_enable = False
        self.port_forward_enable = False
        self.serial: str = None
        self.package_name = package_name
        self.activity_name = activity_name

        self._select_device()

        if package_name is None or not self._check_package_exists():
            raise ValueError(f"Invalid package name: {package_name}")

    def detect_device_abi(self) -> list:
        """Detect the device's CPU architecture.

        Raises:
            RuntimeError: If ABI detection fails.

        Returns:
            list: Device ABIlist (e.g., 'arm64-v8a', 'armeabi-v7a').
        """
        try:
            result = self._run_adb_command([
                "shell", "getprop", "ro.product.cpu.abilist"
            ])
            abi = result.stdout.decode().strip()
            self.logger.debug(f"Detected device ABI list: {abi}")
            return abi.split(",")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to get device ABI list: {e}")
        
    def get_app_pid(self) -> int | None:
        """Get the process ID of the target application.

        Raises:
            ValueError: If package name is not set.

        Returns:
            int: Process ID, or None if app is not running.
        """
        if not self.package_name:
            raise ValueError("Package name not set")
               
        try:
            result = self._run_adb_command([
                "shell", "pidof", self.package_name
            ])
            pid = int(result.stdout.decode().strip())
            self.logger.debug(f"Found app PID: {pid}")
            return pid
        except subprocess.CalledProcessError as e:
            self.logger.debug(f"App {self.package_name} is not running")
            return None
    
    def kill_app(self):
        """Force stop the target application.

        Raises:
            ValueError: If package name is not set.
            RuntimeError: If app termination fails.
        """
        if not self.package_name:
            raise ValueError("Package name not set")
            
        try:
            self._run_adb_command([
                "shell", "am", "force-stop", self.package_name
            ])
            self.logger.info(f"Stopped app: {self.package_name}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to stop app: {e}")
    
    def enable_app_debugging(self):
        """Enable debugging for the target application.

        Raises:
            ValueError: If package name is not set.
            RuntimeError: If debugging setup fails.
        """
        if not self.package_name:
            raise ValueError("Package name not set")
            
        try:
            self._run_adb_command([
                "shell", "am", "set-debug-app", "-w", self.package_name
            ])
            self.debugging_enable = True
            self.logger.info(f"Enabled debugging for: {self.package_name}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to enable debugging: {e}")
        
    def disable_app_debugging(self):
        """Clear debugging for the target application.

        Raises:
            ValueError: If package name is not set.
            RuntimeError: If debugging setup fails.
        """
        if not self.package_name:
            raise ValueError("Package name not set")
            
        try:
            if self.debugging_enable:
                self._run_adb_command([
                    "shell", "am", "clear-debug-app", self.package_name
                ])
                self.debugging_enable = False
                self.logger.info(f"Cleared the previously set-debug-app: {self.package_name}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to clear debugging: {e}")

    def start_app(self) -> int:
        """Start the target application and wait for it to be ready.

        Raises:
            ValueError: If package name is not set.
            RuntimeError: If the adb command fail.
            Exception: If app fails to start.

        Returns:
            int: Process ID of the started application.
        """
        if not self.package_name:
            raise ValueError("Package name not set")
            
        # Prepare start command
        if self.activity_name:
            command = ["shell", "am", "start", "-n", 
                      f"{self.package_name}/{self.activity_name}"]
        else:
            command = ["shell", "monkey", "-p", self.package_name, 
                      "-c", "android.intent.category.LAUNCHER", "1"]
        
        try:
            self.logger.info(f"Trying to start the app: {self.package_name}")
            self._run_adb_command(command)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to start app: {e}")
        
        # Wait for app to start and get PID
        for attempt in range(APP_START_MAX_ATTEMPTS):
            pid = self.get_app_pid()
            if pid:
                self.logger.info(f"App started with PID: {pid}")
                return pid
            
            self.logger.debug(f"Waiting for app to start (attempt {attempt + 1}/{APP_START_MAX_ATTEMPTS})")
            time.sleep(APP_START_RETRY_DELAY_SEC)
        
        raise Exception("App failed to start within timeout period")
    
    def setup_port_forwarding(self, pid: int):
        """Setup JDWP port forwarding.

        Args:
            pid (int): Target process ID.

        Raises:
            RuntimeError: If port forwarding setup fails.
        """
        try:
            self._run_adb_command([
                "forward", f"tcp:{self.jdwp_port}", f"jdwp:{pid}"
            ])
            self.port_forward_enable = True
            self.logger.info(f"Port forwarding setup: tcp:{self.jdwp_port} -> jdwp:{pid}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to setup port forwarding: {e}")

    def remove_port_forwarding(self):
        """Remove JDWP port forwarding.

        Raises:
            RuntimeError: If port forwarding removing fails.
        """
        try:
            if self.port_forward_enable:
                self._run_adb_command([
                    "forward", "--remove", f"tcp:{self.jdwp_port}"
                ])
                self.port_forward_enable = False
                self.logger.info("Port forwarding removed")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to remove port forwarding: {e}")

    def upload_file(self, local_path: Path | str, remote_path: Path | str):
        """Upload a file to the device.

        Args:
            local_path (Union[Path, str]): Local file path.
            remote_path (Union[Path, str]): Remote destination path.

        Raises:
            RuntimeError: If file upload fails.
        """
        if isinstance(local_path, Path):
            local_path = str(local_path)
        if isinstance(remote_path, Path):
            remote_path = str(remote_path)

        try:
            self._run_adb_command(["push", local_path, remote_path])
            self.logger.info(f"Uploaded {local_path} -> {remote_path}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to upload file: {e}")
    
    def remove_file(self, path: Path | str):
        """Remove a file from the device.

        Args:
            path (Union[Path, str]): Remote file path to remove.

        Raises:
            RuntimeError: If file removal fails.
        """
        if isinstance(path, Path):
            path = str(path)

        try:
            self._run_adb_command(["shell", "rm", "-f", path])
            self.logger.debug(f"Removed file: {path}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to remove file: {path}. {e}")

    def _run_adb_command(self, command: list[str]) -> subprocess.CompletedProcess:
        """Execute an ADB command.

        Args:
            command (list[str]): ADB command arguments.

        Returns:
            subprocess.CompletedProcess: Completed process result.
        """
        if not self.serial:
            full_command = ["adb"] + command
        else:
            full_command = ["adb", "-s", self.serial] + command
        self.logger.debug(f"Executing: {' '.join(full_command)}")
        
        return subprocess.run(
            full_command, 
            check=True, 
            capture_output=True,
            timeout=ADB_COMMAND_TIMEOUT
        )
    
    def _check_package_exists(self) -> bool:
        """Check if package name exists.

        Raises:
            RuntimeError: If command execution fails.

        Returns:
            bool: True if package name exists, False otherwise.
        """
        try:
            result = self._run_adb_command([
                "shell", "pm", "list", "packages"
            ])
            if result.returncode == 0:
                result_out = result.stdout.decode()
                for line in result_out.split("\n"):
                    if line.removeprefix("package:") == self.package_name:
                        return True
                return False
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to validate package: {e}")
    
    def _select_device(self):
        """Select target device from available devices."""
        devices = self._get_available_devices()
        
        if len(devices) == 1:
            # Auto-select single device
            self._set_device(devices[0]['serial'])
        else:
            # Let user choose from multiple devices
            self.logger.info("Multiple devices found:")
            for i, device in enumerate(devices):
                    print(f"[{i+1}] {device['serial']}\t{device['status']}")
        
            while True:
                try:
                    choice = input("Choose device number: ").strip()
                    if not choice:
                        continue
                        
                    device_idx = int(choice) - 1
                    if 0 <= device_idx < len(devices):
                        self._set_device(devices[device_idx]['serial'])
                        break
                    else:
                        print(f"Invalid choice. Please enter 1-{len(devices)}")
                        
                except ValueError:
                    print("Invalid input. Please enter a number.")
    
    def _get_available_devices(self) -> list[dict]:
        """Get list of connected Android devices.

        Raises:
            ConnectionError: If ADB connection fails.
            Exception: If no devices connected.

        Returns:
            list[dict]: List of connected ADB devices.
        """
        try:
            output = self._run_adb_command(["devices"])
            output = output.stdout.decode()
            lines = output.strip().split("\n")
            devices = []
            for line in lines[1:]:
                device, status = line.split()
                devices.append({"serial": device, "status": status})
            
            self.logger.debug(f"Found {len(devices)} connected devices")

            if not devices:
                raise Exception("No Android devices connected")
            
            return devices

        except Exception as e:
            raise ConnectionError(f"Failed to connect to ADB server: {e}")
        
    def _set_device(self, serial: str):
        """Set the target device by serial number.

        Args:
            serial (str): Device serial number.

        Raises:
            Exception: If the device serial number is not found. 
        """
        devices = self._get_available_devices()
        if any(serial == device['serial'] for device in devices):
            self.serial = serial
            self.logger.info(f"Selected device: {serial}")
        else:
            raise Exception(f"Device with serial {serial} not found")
    

class CustomLibManager:
    """Manages custom lib."""

    def __init__(self):
        """Initialize the Custom lib manager."""
        self.logger = logging.getLogger(__name__)

    def run(self, path: Path) -> list[Path]:
        """Prepare custom library for injection.

        Args:
            path (Path): Path to custom library/directory.

        Raises:
            FileNotFoundError: If the path doesn't exist.

        Returns:
            list[Path]: files to upload.
        """
        if not path.exists():
            raise FileNotFoundError(f"Path doesn't exist")
        if path.is_dir():
            files_path = [p for p in path.iterdir() if p.is_file()]
        else:
            files_path = [path]
        
        self.logger.info(f"Prepared {len(files_path)} files.")
        return files_path       

class FridaGadgetManager:
    """Manages Frida gadget."""

    def __init__(self,
        device_manager: AndroidDeviceManager,
        frida_gadget_selector: str,
        script_path: Path | str,
        custom_config_file: Path | str,
        interaction_type: str = "listen",
        address: str = DEFAULT_FRIDA_LISTEN_ADDRESS,
        port: int = DEFAULT_FRIDA_PORT
    ):
        """Initialize the Frida gadget manager

        Args:
            device_manager (AndroidDeviceManager): android device object.
            frida_gadget_selector (str): Path to library file, frida gadget version 
                (e.g., '16.1.2') or 'auto' to detect automatically.
            script_path (Path | str): Path to the script to load.
            custom_config_file (Path | str): Path to the custom config file.
            interaction_type (str, optional): Frida gadget interaction types. Defaults to "listen".
            address (str, optional): The interface to listen on. Defaults to "127.0.0.1".
            port (int, optional): The TCP port to listen on. Defaults to 27042.
        """
        self.logger = logging.getLogger(__name__)

        self.frida_config_lpath: Path = None
        self.frida_gadget_lpath: Path = None

        self.device_manager = device_manager
        self.frida_gadget_selector = frida_gadget_selector
        self.custom_config_file = custom_config_file
        self.interaction_type = interaction_type
        self.address = address
        self.port = port
        
        if isinstance(script_path, str):
            self.script_path = Path(script_path)
        else:
            self.script_path = script_path
    
    def run(self) -> list[Path]:
        """Prepare frida gadget library for injection.

        Returns:
            list[Path]: files to upload.
        """
        self._prepare_frida_gadget()
        self._prepare_config_gadget()

        files_to_upload = [self.frida_gadget_lpath, self.frida_config_lpath]
        if self.script_path:
            files_to_upload.append(self.script_path)
        
        return files_to_upload

    def _prepare_frida_gadget(self):
        """Prepare frida gadget for injection.

        Raises:
            FileNotFoundError: If the library is not found.
        """
        abilist = self.device_manager.detect_device_abi()
        abi = self._convert_abi_to_frida(abilist)
        
        if self.frida_gadget_selector.strip().lower() == "auto":
            version = self._get_frida_version()
            self.frida_gadget_lpath = self._download_gadget(version, abi)
        
        elif re.match(r'^\d+\.\d+\.\d+$', self.frida_gadget_selector):
            self.frida_gadget_lpath = self._download_gadget(self.frida_gadget_selector, abi)
        
        else:
            self.frida_gadget_lpath = Path(self.frida_gadget_selector)
            if not self.frida_gadget_lpath.exists() or self.frida_gadget_lpath.suffix != ".so":
                raise FileNotFoundError(f"Library file not found or not valid extension")
            self.logger.info(f"Using custom frida library: {self.frida_gadget_lpath}")
        
    def _prepare_config_gadget(self):
        """Prepare frida config gadget for injection.

        Raises:
            Exception: If the interaction mode is not valid.
        """
        frida_filename = self.frida_gadget_lpath.name
        config_filename = f"{frida_filename.rstrip('.so')}.config.so"

        if self.interaction_type == "listen":
            config = self._prepare_config_listen_gadget()
            config_str = json.dumps(config, ensure_ascii=False, indent=2)
        elif self.interaction_type == "script":
            config = self._prepare_config_script_gadget()
            config_str = json.dumps(config, ensure_ascii=False, indent=2)
        elif self.interaction_type == "custom":
            with open(self.custom_config_file, "r", encoding="utf-8") as f:
                config_str = f.read()
        else:
            raise Exception("Interaction mode is not valid")
        
        with open(config_filename, "w", encoding="utf-8") as f:
            f.write(config_str)
        
        self.frida_config_lpath = Path(config_filename)
    
    def _prepare_config_listen_gadget(self) -> dict:
        """Prepare frida config gadget with listen interaction.

        Returns:
            dict: The listen config gadget.
        """
        config = {
                "interaction": {
                        "type": "listen",
                        "address": self.address,
                        "port": self.port,
                        "on_port_conflict": "fail",
                        "on_load": "resume",
                    }
            }
        return config

    def _prepare_config_script_gadget(self) -> dict:
        """Prepare frida config gadget with script interaction.

        Returns:
            dict: The script config gadget.
        """
        config = {
                "interaction": {
                        "type": "script",
                        "path": self.script_path.name
                    }
            }
        return config
    
    def _create_download_url(self, version: str, abi: str) -> str:
        """Create the download URL for Frida gadget.

        Args:
            version (str): Frida gadget version to download.
            abi (str): ABI of the device.

        Returns:
            str: url to download frida gadget.
        """
        return FRIDA_GADGET_URL_TEMPLATE.format(version=version, abi=abi)

    def _extract_filename_from_url(self, url: str) -> str:
        """Extract filename from URL, removing .xz extension.

        Args:
            url (str): The URL string from which to extract the filename.

        Returns:
            str: The filename portion of the URL path, with a trailing `.xz` removed.
        """
        parsed_url = urlparse(url)
        return os.path.basename(parsed_url.path).rstrip(".xz")
    
    def _convert_abi_to_frida(self, abilist: list) -> str:
        """Convert an Android ABI string (e.g. 'armeabi-v7a', 'arm64-v8a', 'x86_64')
        to a Frida-compatible architecture string (e.g. 'arm', 'arm64', 'x86', 'x86_64').

        Args:
            abilist (list): ABI name (from ro.product.cpu.abi prop).

        Raises:
            ValueError: If the ABI is unknown.

        Returns:
            str: Frida architecture.
        """
        mapping = {
            # 32-bit ARM
            "armeabi": "arm",
            "armeabi-v7a": "arm",

            # 64-bit ARM
            "arm64-v8a": "arm64",

            # x86
            "x86": "x86",

            # x86_64
            "x86_64": "x86_64"
        }

        for abi in abilist:
            if abi in mapping:
                return mapping[abi]
        
        raise ValueError(f"Unknown ABI(s): {abilist}")
    
    def _get_frida_version(self) -> str:
        """Get the installed Frida version.

        Raises:
            RuntimeError: If Frida is not installed or version detection fails.

        Returns:
            str: Frida version string.
        """
        if shutil.which("frida") is None:
            self.logger.error(f"Failed to get Frida version. Is Frida installed?")
            raise RuntimeError(f"Failed to get Frida version")
        
        try:
            result = subprocess.run(
                ["frida", "--version"],
                check=True,
                capture_output=True,
                timeout=10
            )
            version = result.stdout.decode().strip()
            self.logger.debug(f"Detected Frida version: {version}")
            return version
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to get Frida version: {e}")

    def _download_gadget(self, version: str, abi: str) -> Path:
        """Download and decompress Frida gadget for specified version and ABI.
        
        Args:
            version (str): Frida version.
            abi (str): Target device ABI.
        
        Raises:
            RuntimeError: If download or decompression fails.
        
        Returns:
            Path: filename of downloaded gadget file.
        """
        url = self._create_download_url(version, abi)
        filename = self._extract_filename_from_url(url)
        
        self.logger.info(f"Downloading Frida gadget {version} for {abi}")
        self.logger.debug(f"Download URL: {url}")
        
        try:
            # Download compressed file
            with urlopen(url, timeout=DOWNLOAD_TIMEOUT_SEC) as response:
                if response.status != 200:
                    raise RuntimeError(f"HTTP {response.status}: {response.reason}")
                
                # Decompress and save
                decompressor = lzma.LZMADecompressor()
                decompressed_data = bytearray()
                downloaded = 0
                
                while True:
                    chunk = response.read(DOWNLOAD_CHUNK_SIZE_BYTES)
                    if not chunk:
                        break
                    decompressed_data.extend(decompressor.decompress(chunk))
                    downloaded += len(chunk)
            
            # Write decompressed data to file
            output_path = Path(filename)
            with open(output_path, "wb") as f:
                f.write(decompressed_data)
            
            self.logger.info(f"Frida gadget downloaded: {output_path}")
            return output_path
            
        except (URLError, HTTPError) as e:
            raise RuntimeError(f"Failed to download Frida gadget: {e}")
        except lzma.LZMAError as e:
            raise RuntimeError(f"Failed to decompress Frida gadget: {e}")


class LibraryInjector:
    """Main class for managing the library injection process."""
    
    def __init__(self,
        device_manager: AndroidDeviceManager,
        verbose: bool = False
    ):
        """Initialize the library injector.

        Args:
            device_manager (AndroidDeviceManager): device manager.
            verbose (bool, optional): Enable verbose logging. Defaults to False.
        """
        self.device_manager = device_manager
        self.logger = logging.getLogger(__name__)
        self._setup_logging(verbose)
    
    def _setup_logging(self, verbose: bool):
        """Setup logging configuration.

        Args:
            verbose (bool): Enable verbose logging.
        """
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def _convert_to_jdwp_format(self, input_string: str) -> tuple[str, str]:
        """Convert a fully-qualified class name and method name into JDWP format.

        This function takes a string representing a fully-qualified class name and method name
        and converts it into the format used in JDWP (Java Debug Wire Protocol) for class and
        method references.

        Args:
            input_string (str): The fully-qualified class name and method name in the format "package.ClassName.method".

        Raises:
            ValueError: If the input string is not in the expected format.

        Returns:
            tuple[str, str]: A tuple containing:
                - Class name in JDWP/JVM format (e.g., "Lcom/example/MyClass;")
                - Method name as-is (e.g., "myMethod")
        """
        i = input_string.rfind(".")
        if i == -1:
            raise ValueError("Invalid input format. Cannot parse path.")

        break_on_class = "L" + input_string[:i].replace(".", "/") + ";"
        break_on_method = input_string[i + 1 :]

        return break_on_class, break_on_method
    
    def _reorder_files(self, path_list: list[Path]) -> list[Path]:
        """
        Creates a new list with the first shared library (.so) moved to the beginning.

        Args:
            path_list (list[Path]): A list of paths to search.

        Raises:
            ValueError: If no shared library (.so) file is found in the list.

        Returns:
            Path: The updated list with the first .so library at index 0.
        """
        reordered_list = path_list.copy()
    
        for i, f in enumerate(reordered_list):
            if f.suffix == ".so":
                # Move .so file to the beginning
                reordered_list.insert(0, reordered_list.pop(i))
                self.logger.debug(f"Library to load: {reordered_list[0]}")
                return reordered_list
        
        raise ValueError("No shared library (.so) file found in path list")
    
    def _clear(self):
        """Disable app debugging and remove the port forwarding."""
        self.logger.info("Cleaning up...")
        self.device_manager.disable_app_debugging()
        self.device_manager.remove_port_forwarding()
        self.logger.info("Cleaning complete")
    
    def inject_library(
        self,
        break_on: str,
        path_list: list[Path],
        restart: bool,
        clear: bool,
        suspended: bool,
        keep_files: bool,
        delay: int = DELAY
    ) -> bool:
        """Perform the library injection process.

        Args:
            path_list (list[Path]): List of file to upload with the first .so library at index 0.
            restart (bool): If the application should be restarted.
            clear (bool): Clear after injection.
            delay: (int): Delay between operations.

        Returns:
            bool: True if injection was successful.
        """
        self.cleared = False

        magic_dir_path = f"/data/data/{self.device_manager.package_name}/{INJECTION_DIR_NAME}"
        
        try:
            break_on_class, break_on_method = self._convert_to_jdwp_format(break_on)

            # Reorder files
            self._reorder_files(path_list)

            if restart:
                # Stop app if running
                if self.device_manager.get_app_pid():
                    self.logger.info("Stopping running app instance")
                    self.device_manager.kill_app()
                
                # Enable debugging and start app
                self.device_manager.enable_app_debugging()
                time.sleep(delay)
                pid = self.device_manager.start_app()
            else:
                pid = self.device_manager.get_app_pid()
                if not pid:
                    self.logger.error("The application is not running")
                    return False
            
            # Setup JDWP forwarding
            self.device_manager.setup_port_forwarding(pid)
            
            # Wait for app to be ready
            self.logger.info("Waiting for app to be ready...")
            time.sleep(delay)
            
            # Perform injection via JDWP
            self.logger.info("Starting JDWP injection...")

            # Initializer of JDWP (Perform cleaning and dir creation)
            with JDWPClient("127.0.0.1", self.device_manager.jdwp_port) as cli:
                rId = cli.set_breakpoint(
                    break_on_class=break_on_class,
                    break_on_method=break_on_method,
                    suspendPolicy=cli.SUSPEND_EVENTTHREAD
                )
                tId = cli.run(resume=True, clear_breakpoint=True, rId=rId)

                # Remove if lib dir already exist
                cli.exec_payload(command=f"rm -rf {magic_dir_path}", threadId=tId)
                time.sleep(delay)
                # Create dir lib
                cli.exec_payload(command=f"mkdir {magic_dir_path}", threadId=tId)
                time.sleep(delay)

                # Prepare and upload lib
                for lpath in path_list:
                    filename = lpath.name
                    r_tmp_path = f"{REMOTE_TEMP_PATH}/{filename}"
                    self.device_manager.upload_file(local_path=lpath, remote_path=r_tmp_path)
                    cli.exec_payload(
                        command=f"cp {r_tmp_path} {magic_dir_path}/{filename}",
                        threadId=tId
                    )
                    self.device_manager.remove_file(r_tmp_path)
                    time.sleep(delay)
                    
                # Sending loading file ..... -> by default it's always the first path
                cli.load_library(
                    library=f"{magic_dir_path}/{path_list[0].name}",
                    threadId=tId
                )
                
                self.logger.info("Library injection successful!")
                time.sleep(delay)
                
                if keep_files:
                    cli.exec_payload(command=f"rm -rf {magic_dir_path}", threadId=tId)

                if suspended:
                    thread_suspended = cli._get_thread_by_id(tId)
                    print(f"Execution of the '{thread_suspended}' thread is suspended.")
                    while True:
                        choice = input("Type 'resume' to continue execution. ").strip()
                        if choice == "resume":
                            break
                    
                    if clear:
                        time.sleep(delay)
                        self._clear()
                        self.cleared = True
            
                return True
            
        except Exception as e:
            self.logger.error(f"Injection process failed: {e}")
            return False
        
        finally:
            if clear and not self.cleared:
                time.sleep(delay)
                self._clear()


def setup_argument_parser() -> argparse.ArgumentParser:
    """Setup and configure argument parser."""
    parser = argparse.ArgumentParser(
        description="frida-jdwp-loader",
        epilog="""Examples:
        python frida-jdwp-loader.py frida -n com.example.myapplication
        python frida-jdwp-loader.py frida -n com.example.myapplication -g 16.1.2
        python frida-jdwp-loader.py frida -n com.example.myapplication -s
        python frida-jdwp-loader.py frida -n com.example.myapplication -a .MainActivity
        python frida-jdwp-loader.py frida -n com.example.myapplication -i listen -L 0.0.0.0 -P 27043
        python frida-jdwp-loader.py frida -n com.example.myapplication -i script -l script.js
        python frida-jdwp-loader.py custom -n com.example.myapplication -l /path/to/lib_directory/
        """,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    common_parser = argparse.ArgumentParser(add_help=False)
    # App configuration
    common_parser.add_argument(
        "-n", "--package",
        type=str,
        required=True,
        help="Target Android package name (e.g., com.example.app)",
        metavar="PACKAGE_NAME",
        dest="package_name"
    )
    common_parser.add_argument(
        "-a", "--activity",
        type=str,
        help="Target activity name (Default: launcher activity)",
        metavar="ACTIVITY_NAME",
        dest="activity_name"
    )
    common_parser.add_argument(
        "-m", "--mode",
        default="spawn",
        choices=["spawn", "attach"],
        help=("Select mode:\n"
                    "\tspawn (Default)\n" 
                    "\tattach"),
        metavar="MODE",
        dest="mode"
    )
    common_parser.add_argument(
        "-b", "--break-on",
        default=None,
        type=str,
        help=("Java method to break on for injection (full path required)\n"
                "Default depends on mode:\n"
                "\tspawn -> android.app.Application.onCreate\n"
                "\tattach -> android.app.Activity.onStart"),
        metavar="JAVA_METHOD",
        dest="break_on"
    )
    common_parser.add_argument(
        "-p", "--port",
        default=DEFAULT_JDWP_PORT,
        type=int,
        help="Local port number for JDWP forwarding (Default: 8715)",
        metavar="JDWP_PORT",
        dest="jdwp_port"
    )
    common_parser.add_argument(
        "-nc", "--no-clear",
        action="store_false",
        help="Don't clear after injection",
        dest="clear"
    )
    common_parser.add_argument(
        "-d", "--delay",
        default=DELAY,
        type=int,
        help="Delay between operations (Default: 2)",
        dest="delay"
    )
    common_parser.add_argument(
        "-s", "--suspended",
        action="store_true",
        help="Keep the thread that hits the breakpoint suspended after spawning the app",
        dest="suspended"
    )
    common_parser.add_argument(
        "-k", "--keep-files",
        action="store_false",
        help="Keep uploaded files after execution (default: files are removed)",
        dest="keep_files"
    )
    common_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging output",
        dest="verbose"
    )

    subparsers = parser.add_subparsers(
        required=True,
        help='Choose the execution mode',
        metavar='MODE',
        dest='execution_mode'
    )

    # Frida parser
    frida_parser = subparsers.add_parser(
        "frida",
        help="Run in Frida mode",
        formatter_class=argparse.RawTextHelpFormatter
    )
    frida_parser.add_argument(
        "-g", "--gadget",
        default="auto",
        type=str,
        help=("Could be one of the following:\n"
            "\tPath to the frida gadget library file\n"
            "\tFrida version (e.g., '16.6.6')\n"
            "\tauto, to automatically detect (Default)"),
        metavar="GADGET",
        dest="gadget"
    )
    frida_parser.add_argument(
        "-i", "--interaction",
        default="listen",
        type=str,
        choices=['listen', 'script', "custom"],
        help='Interaction mode (Default: listen)',
        dest="interaction"
    )
    frida_parser.add_argument(
        "-L", "--listen",
        default=DEFAULT_FRIDA_LISTEN_ADDRESS,
        type=str,
        help=("Listen on ADDRESS (used with --interaction listener)\n"
            "(Default: 127.0.0.1)"),
        metavar="ADDRESS",
        dest="address"
    )
    frida_parser.add_argument(
        "-P", "--frida-port",
        default=DEFAULT_FRIDA_PORT,
        type=int,
        help=("Listen on PORT (used with --interaction listener)\n"
            "(Default: 27042)"),
        metavar="PORT",
        dest="frida_port"
    )
    frida_parser.add_argument(
        "-l", "--load",
        type=str,
        help=("load SCRIPT (Required with --interaction script)"),
        metavar="SCRIPT",
        dest="script"
    )
    frida_parser.add_argument(
        "-f", "--config-file",
        type=str,
        help=("load CONFIG-FILE (Required with --interaction custom)"),
        metavar="CONFIG",
        dest="config_file"
    )
    for action in common_parser._actions:
        if not isinstance(action, argparse._HelpAction):
            frida_parser._add_action(action)

    # Custom lib parser
    custom_lib_parser = subparsers.add_parser(
        "custom",
        help="Run in Custom mode",
        formatter_class=argparse.RawTextHelpFormatter
    )
    custom_lib_parser.add_argument(
        "-l", "--lib-path",
        required=True,
        type=str,
        help="Path to the custom library file/directory to inject",
        metavar="LIB_PATH",
        dest="lib_path"
    )
    for action in common_parser._actions:
        if not isinstance(action, argparse._HelpAction):
            custom_lib_parser._add_action(action)

    return parser

def main() -> int:
    """
    Main entry point for the library injector.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    parser = setup_argument_parser()
    args = parser.parse_args()

    if shutil.which("adb") is None:
        print("adb not found in PATH")
        return 1

    if args.break_on is None:
        if args.mode == "spawn":
            args.break_on = BREAK_ON_SPAWN_DEFAULT
        elif args.mode == "attach":
            args.break_on = BREAK_ON_ATTACH_DEFAULT
        else:
            print("Invalid mode")
            return 1

    if args.execution_mode == "frida":
        if args.interaction == "listen" and args.script is not None:
            print("ERROR: You cannot use `listen` interaction with a script")
            return 1
        if args.interaction == "script" and args.script is None:
            print("ERROR: `script` interaction requires --load SCRIPT")
            return 1
        if args.interaction == "custom" and args.config_file is None:
            print("ERROR: `custom` interaction requires --config-file CONFIG")
            return 1
        
        if args.script is not None and not os.path.exists(args.script):
            print(f"ERROR: {args.script} file doesn't exist")
            return 1

        if args.config_file is not None and not os.path.exists(args.config_file):
            print(f"ERROR: {args.config_file} file doesn't exist")
            return 1
        
    elif args.execution_mode == "custom":
        if args.lib_path is not None and not os.path.exists(args.lib_path):
            print(f"ERROR: {args.lib_path} file doesn't exist")
            return 1

    try:
        # Initialize Android device manager
        device_manager = AndroidDeviceManager(package_name=args.package_name, activity_name=args.activity_name, jdwp_port=args.jdwp_port)
        
        # Initialize injector
        injector = LibraryInjector(device_manager = device_manager, verbose = args.verbose)

        # Perform preparation
        restart = True if args.mode == 'spawn' else False
        if args.execution_mode == "frida":
            path_list = FridaGadgetManager(
                    device_manager, 
                    frida_gadget_selector=args.gadget,
                    interaction_type=args.interaction,
                    script_path=args.script,
                    custom_config_file=args.config_file,
                    address=args.address,
                    port=args.frida_port
                ).run()
        elif args.execution_mode == "custom":
            path_list = CustomLibManager().run(Path(args.lib_path))

        # Perform injection
        success = injector.inject_library(
            break_on=args.break_on,
            restart=restart,
            path_list=path_list,
            clear=args.clear,
            suspended=args.suspended,
            keep_files=args.keep_files,
            delay=args.delay
        )
            
        return 0 if success else 1

    except KeyboardInterrupt:
        print("Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())