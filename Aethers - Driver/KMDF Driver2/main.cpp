// Version cleaned by AI
// It was full of junk code and much more, and decided to leave it more "readable"

#include <ntddk.h>
#include <ntstrsafe.h>

 extern "C" {
    NTKERNELAPI NTSTATUS ObOpenObjectByPointer(
        PVOID Object,
        ULONG HandleAttributes,
        PACCESS_STATE PassedAccessState,
        ACCESS_MASK DesiredAccess,
        POBJECT_TYPE ObjectType,
        KPROCESSOR_MODE AccessMode,
        PHANDLE Handle
    );

    NTKERNELAPI NTSTATUS IoCreateDriver(
        PUNICODE_STRING DriverName,
        PDRIVER_INITIALIZE InitializationFunction
    );

    NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
        HANDLE ProcessId,
        PEPROCESS* Process
    );

    NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    );

    NTKERNELAPI NTSTATUS ZwLockFile(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        PLARGE_INTEGER ByteOffset,
        PLARGE_INTEGER Length,
        ULONG Key,
        BOOLEAN FailImmediately,
        BOOLEAN ExclusiveLock
    );

    NTKERNELAPI NTSTATUS ZwUnlockFile(
        HANDLE FileHandle,
        PLARGE_INTEGER ByteOffset,
        PLARGE_INTEGER Length,
        ULONG Key
    );

     NTKERNELAPI NTSTATUS ZwDuplicateObject(
        HANDLE SourceProcessHandle,
        HANDLE SourceHandle,
        HANDLE TargetProcessHandle,
        PHANDLE TargetHandle,
        ACCESS_MASK DesiredAccess,
        ULONG HandleAttributes,
        ULONG Options
    );

     NTKERNELAPI PEPROCESS IoGetRequestorProcess(
        PIRP Irp
    );
}

// Define IOCTL codes
#define IOCTL_AETHERS_OPEN_PROCESS             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AETHERS_READ_WRITE_MEMORY        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AETHERS_LOCK_UNLOCK_FILE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_AETHERS_DELETE_FILE              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

 typedef enum {
    AETHERS_OPEN_PROCESS = 1,
    AETHERS_READ_WRITE_MEMORY,
    AETHERS_LOCK_UNLOCK_FILE,
    AETHERS_DELETE_FILE
} AETHERS_OPERATION_TYPE;

 #pragma pack(push, 1)
typedef struct _AETHERS_OPERATION_REQUEST {
    AETHERS_OPERATION_TYPE operation;
    union {
        struct {
            DWORD pid;  
            ACCESS_MASK access;
        } openProcess;
        struct {
            DWORD pid;  
            PVOID targetAddress;
            PVOID buffer;
            SIZE_T size;
            BOOLEAN isWrite;
        } readWriteMemory;
        struct {
            WCHAR filePath[260];
            BOOLEAN lock;
        } lockUnlockFile;
        struct {
            WCHAR filePath[260];
        } deleteFile;
    } data;
} AETHERS_OPERATION_REQUEST, * PAETHERS_OPERATION_REQUEST;

 typedef struct _AETHERS_OPERATION_RESPONSE {
    HANDLE processHandle;
} AETHERS_OPERATION_RESPONSE, * PAETHERS_OPERATION_RESPONSE;
#pragma pack(pop)

 DRIVER_UNLOAD UnloadDrv;
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS InitDriver(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS DispatchHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS IoController(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS AethersOpenProcess(DWORD pid, ACCESS_MASK access, PEPROCESS callerProcess, PHANDLE processHandle);
NTSTATUS AethersReadWriteMemory(DWORD pid, PVOID targetAddress, PVOID buffer, SIZE_T size, BOOLEAN isWrite);
NTSTATUS AethersLockUnlockFile(PCWSTR filePath, BOOLEAN lock);
NTSTATUS AethersDeleteFile(PCWSTR filePath);

 NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    return IoCreateDriver(NULL, &InitDriver);
}

 NTSTATUS InitDriver(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = NULL;

     UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;
    RtlInitUnicodeString(&deviceName, L"\\Device\\AethersScannerZah");
    RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\AethersScannerZah");

     status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &DeviceObject
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Aethers] IoCreateDevice failed with status: 0x%X\n", status);
        return status;
    }

     status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Aethers] IoCreateSymbolicLink failed with status: 0x%X\n", status);
        IoDeleteDevice(DeviceObject);
        return status;
    }

     for (ULONG i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = UnsupportedDispatch;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoController;
    DriverObject->DriverUnload = UnloadDrv;

     DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

     return status;
}

 NTSTATUS DispatchHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

 NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    DbgPrint("[Aethers] Unsupported IRP_MJ code: 0x%X\n", Irp->Tail.Overlay.CurrentStackLocation->MajorFunction);
    return STATUS_NOT_SUPPORTED;
}

 VOID UnloadDrv(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symbolicLinkName;
    RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\AethersScannerZah");
    IoDeleteSymbolicLink(&symbolicLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);
    DbgPrint("[Aethers] Driver unloaded successfully.\n");
}

 NTSTATUS IoController(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;

    PAETHERS_OPERATION_REQUEST request = (PAETHERS_OPERATION_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    PAETHERS_OPERATION_RESPONSE response = (PAETHERS_OPERATION_RESPONSE)Irp->AssociatedIrp.SystemBuffer;

    if (request == NULL) {
        DbgPrint("[Aethers] Received NULL request buffer.\n");
        status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = bytesReturned;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

     PEPROCESS callerProcess = IoGetRequestorProcess(Irp);

    switch (ioControlCode) {
    case IOCTL_AETHERS_OPEN_PROCESS:
        if (inputBufferLength >= sizeof(AETHERS_OPERATION_REQUEST)) {
            HANDLE duplicatedHandle = NULL;
            status = AethersOpenProcess(
                request->data.openProcess.pid,
                request->data.openProcess.access,
                callerProcess,
                &duplicatedHandle
            );

            if (NT_SUCCESS(status)) {
                response->processHandle = duplicatedHandle;
                bytesReturned = sizeof(AETHERS_OPERATION_RESPONSE);
                DbgPrint("[Aethers] OpenProcess succeeded for PID: %lu. Duplicated Handle: 0x%p\n", request->data.openProcess.pid, duplicatedHandle);
            }
            else {
                response->processHandle = NULL;
                bytesReturned = sizeof(AETHERS_OPERATION_RESPONSE);
                DbgPrint("[Aethers] OpenProcess failed for PID: %lu. Status: 0x%X\n", request->data.openProcess.pid, status);
            }
        }
        else {
            DbgPrint("[Aethers] IOCTL_AETHERS_OPEN_PROCESS: Invalid input buffer length.\n");
            status = STATUS_INFO_LENGTH_MISMATCH;
        }
        break;

    case IOCTL_AETHERS_READ_WRITE_MEMORY:
        if (inputBufferLength >= sizeof(AETHERS_OPERATION_REQUEST)) {
            status = AethersReadWriteMemory(
                request->data.readWriteMemory.pid,
                request->data.readWriteMemory.targetAddress,
                request->data.readWriteMemory.buffer,
                request->data.readWriteMemory.size,
                request->data.readWriteMemory.isWrite
            );

            if (NT_SUCCESS(status)) {
                bytesReturned = sizeof(AETHERS_OPERATION_RESPONSE);
                DbgPrint("[Aethers] Read/Write Memory succeeded for PID: %lu.\n", request->data.readWriteMemory.pid);
            }
            else {
                bytesReturned = 0;
                DbgPrint("[Aethers] Read/Write Memory failed for PID: %lu. Status: 0x%X\n", request->data.readWriteMemory.pid, status);
            }
        }
        else {
            DbgPrint("[Aethers] IOCTL_AETHERS_READ_WRITE_MEMORY: Invalid input buffer length.\n");
            status = STATUS_INFO_LENGTH_MISMATCH;
        }
        break;

    case IOCTL_AETHERS_LOCK_UNLOCK_FILE:
        if (inputBufferLength >= sizeof(AETHERS_OPERATION_REQUEST)) {
            status = AethersLockUnlockFile(
                request->data.lockUnlockFile.filePath,
                request->data.lockUnlockFile.lock
            );

            if (NT_SUCCESS(status)) {
                bytesReturned = sizeof(AETHERS_OPERATION_RESPONSE);
                DbgPrint("[Aethers] Lock/Unlock File succeeded for: %ws.\n", request->data.lockUnlockFile.filePath);
            }
            else {
                bytesReturned = 0;
                DbgPrint("[Aethers] Lock/Unlock File failed for: %ws. Status: 0x%X\n", request->data.lockUnlockFile.filePath, status);
            }
        }
        else {
            DbgPrint("[Aethers] IOCTL_AETHERS_LOCK_UNLOCK_FILE: Invalid input buffer length.\n");
            status = STATUS_INFO_LENGTH_MISMATCH;
        }
        break;

    case IOCTL_AETHERS_DELETE_FILE:
        if (inputBufferLength >= sizeof(AETHERS_OPERATION_REQUEST)) {
            status = AethersDeleteFile(
                request->data.deleteFile.filePath
            );

            if (NT_SUCCESS(status)) {
                bytesReturned = sizeof(AETHERS_OPERATION_RESPONSE);
                DbgPrint("[Aethers] Delete File succeeded for: %ws.\n", request->data.deleteFile.filePath);
            }
            else {
                bytesReturned = 0;
                DbgPrint("[Aethers] Delete File failed for: %ws. Status: 0x%X\n", request->data.deleteFile.filePath, status);
            }
        }
        else {
            DbgPrint("[Aethers] IOCTL_AETHERS_DELETE_FILE: Invalid input buffer length.\n");
            status = STATUS_INFO_LENGTH_MISMATCH;
        }
        break;

    default:
        DbgPrint("[Aethers] Received unknown IOCTL code: 0x%X\n", ioControlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

 NTSTATUS AethersOpenProcess(DWORD pid, ACCESS_MASK access, PEPROCESS callerProcess, PHANDLE processHandle) {
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS targetProcess = NULL;
    HANDLE kernelHandle = NULL;
    HANDLE duplicatedHandle = NULL;

     status = PsLookupProcessByProcessId((HANDLE)pid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Aethers] PsLookupProcessByProcessId failed. PID: %lu Status: 0x%X\n", pid, status);
        return status;
    }

     status = ObOpenObjectByPointer(
        targetProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        access,
        *PsProcessType,
        KernelMode,
        &kernelHandle
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Aethers] ObOpenObjectByPointer failed. Status: 0x%X\n", status);
        ObDereferenceObject(targetProcess);
        return status;
    }

     HANDLE callerHandle = NULL;
    status = ObOpenObjectByPointer(
        callerProcess,
        0,
        NULL,
        DUPLICATE_SAME_ACCESS,
        *PsProcessType,
        KernelMode,
        &callerHandle
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Aethers] ObOpenObjectByPointer (caller) failed. Status: 0x%X\n", status);
        ZwClose(kernelHandle);
        ObDereferenceObject(targetProcess);
        return status;
    }

     status = ZwDuplicateObject(
        kernelHandle,
        kernelHandle,
        callerHandle,
        &duplicatedHandle,
        access,
        0,
        DUPLICATE_SAME_ACCESS
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Aethers] ZwDuplicateObject failed. Status: 0x%X\n", status);
        ZwClose(kernelHandle);
        ZwClose(callerHandle);
        ObDereferenceObject(targetProcess);
        return status;
    }

     *processHandle = duplicatedHandle;
    DbgPrint("[Aethers] Process handle duplicated successfully. Handle: 0x%p\n", duplicatedHandle);

    // Clean up
    ZwClose(kernelHandle);
    ZwClose(callerHandle);
    ObDereferenceObject(targetProcess);

    return status;
}

 NTSTATUS AethersReadWriteMemory(DWORD pid, PVOID targetAddress, PVOID buffer, SIZE_T size, BOOLEAN isWrite) {
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS targetProcess = NULL;

     status = PsLookupProcessByProcessId((HANDLE)pid, &targetProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[Aethers] PsLookupProcessByProcessId failed. PID: %lu Status: 0x%X\n", pid, status);
        return status;
    }

    SIZE_T bytesTransferred = 0;
    __try {
        if (isWrite) {
             ProbeForRead(buffer, size, sizeof(UCHAR));
             status = MmCopyVirtualMemory(
                PsGetCurrentProcess(),
                buffer,
                targetProcess,
                targetAddress,
                size,
                KernelMode,
                &bytesTransferred
            );
            if (NT_SUCCESS(status)) {
                DbgPrint("[Aethers] Memory written successfully. PID: %lu Address: %p Size: %llu\n", pid, targetAddress, (unsigned long long)size);
            }
            else {
                DbgPrint("[Aethers] MmCopyVirtualMemory (write) failed. Status: 0x%X\n", status);
            }
        }
        else {
             ProbeForWrite(buffer, size, sizeof(UCHAR));
             status = MmCopyVirtualMemory(
                targetProcess,
                targetAddress,
                PsGetCurrentProcess(),
                buffer,
                size,
                KernelMode,
                &bytesTransferred
            );
            if (NT_SUCCESS(status)) {
                DbgPrint("[Aethers] Memory read successfully. PID: %lu Address: %p Size: %llu\n", pid, targetAddress, (unsigned long long)size);
            }
            else {
                DbgPrint("[Aethers] MmCopyVirtualMemory (read) failed. Status: 0x%X\n", status);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        DbgPrint("[Aethers] Exception in MmCopyVirtualMemory. Status: 0x%X\n", status);
    }

    ObDereferenceObject(targetProcess);
    return status;
}

 NTSTATUS AethersLockUnlockFile(PCWSTR filePath, BOOLEAN lock) {
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING uniName;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE fileHandle = NULL;

     RtlInitUnicodeString(&uniName, filePath);
    InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

     status = ZwCreateFile(
        &fileHandle,
        FILE_GENERIC_READ | SYNCHRONIZE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Aethers] ZwCreateFile failed for %ws. Status: 0x%X\n", filePath, status);
        return status;
    }

    LARGE_INTEGER byteOffset;
    byteOffset.QuadPart = 0;
    LARGE_INTEGER length;
    length.QuadPart = MAXLONGLONG;

    if (lock) {
         status = ZwLockFile(
            fileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatusBlock,
            &byteOffset,
            &length,
            0,
            FALSE,
            FALSE
        );

        if (NT_SUCCESS(status)) {
            DbgPrint("[Aethers] File locked successfully: %ws\n", filePath);
        }
        else {
            DbgPrint("[Aethers] ZwLockFile failed for %ws. Status: 0x%X\n", filePath, status);
        }
    }
    else {
         status = ZwUnlockFile(
            fileHandle,
            &byteOffset,
            &length,
            0
        );

        if (NT_SUCCESS(status)) {
            DbgPrint("[Aethers] File unlocked successfully: %ws\n", filePath);
        }
        else {
            DbgPrint("[Aethers] ZwUnlockFile failed for %ws. Status: 0x%X\n", filePath, status);
        }
    }

    ZwClose(fileHandle);
    return status;
}

 NTSTATUS AethersDeleteFile(PCWSTR filePath) {
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING uniName;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatusBlock;
    HANDLE fileHandle = NULL;

     RtlInitUnicodeString(&uniName, filePath);
    InitializeObjectAttributes(&objAttr, &uniName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

     status = ZwCreateFile(
        &fileHandle,
        DELETE,
        &objAttr,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        DbgPrint("[Aethers] ZwCreateFile (DELETE) failed for %ws. Status: 0x%X\n", filePath, status);
        return status;
    }

    FILE_DISPOSITION_INFORMATION fileDisposition = { 0 };
    fileDisposition.DeleteFile = TRUE;

     status = ZwSetInformationFile(
        fileHandle,
        &ioStatusBlock,
        &fileDisposition,
        sizeof(FILE_DISPOSITION_INFORMATION),
        FileDispositionInformation
    );

    if (NT_SUCCESS(status)) {
        DbgPrint("[Aethers] File deleted successfully: %ws\n", filePath);
    }
    else {
        DbgPrint("[Aethers] ZwSetInformationFile (Delete) failed for %ws. Status: 0x%X\n", filePath, status);
    }

    ZwClose(fileHandle);
    return status;
}
