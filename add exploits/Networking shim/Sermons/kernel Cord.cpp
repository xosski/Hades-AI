kernel Cord
{	

	#include <ntddk.h>
#include <ntddkbd.h>
#include <wdf.h>

#define IOCTL_SEND_KEY CTL_CODE(FILE_DEVICE_KEYBOARD, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _KEYBOARD_INPUT_DATA {
    USHORT MakeCode;
    USHORT Flags;
} KEYBOARD_INPUT_DATA, *PKEYBOARD_INPUT_DATA;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
NTSTATUS KeyboardDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS KeyboardDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID DriverUnload(PDRIVER_OBJECT DriverObject);

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KeyboardMacroDriver");
    UNICODE_STRING SymbolicLink = RTL_CONSTANT_STRING(L"\\??\\KeyboardMacro");

    PDEVICE_OBJECT DeviceObject = NULL;
    NTSTATUS status = IoCreateDevice(DriverObject,
                                     0,
                                     &DeviceName,
                                     FILE_DEVICE_KEYBOARD,
                                     FILE_DEVICE_SECURE_OPEN,
                                     FALSE,
                                     &DeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&SymbolicLink, &DeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(DeviceObject);
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = KeyboardDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = KeyboardDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KeyboardDispatchIoctl;

    return STATUS_SUCCESS;
}

NTSTATUS KeyboardDispatchCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS KeyboardDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    if (IoStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_SEND_KEY) {
        if (IoStackLocation->Parameters.DeviceIoControl.InputBufferLength >= sizeof(KEYBOARD_INPUT_DATA)) {
            PKEYBOARD_INPUT_DATA KeyData = (PKEYBOARD_INPUT_DATA)Irp->AssociatedIrp.SystemBuffer;

            // Log or simulate the keypress
            DbgPrint("Simulating key: MakeCode=%d, Flags=%d\n", KeyData->MakeCode, KeyData->Flags);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING SymbolicLink = RTL_CONSTANT_STRING(L"\\??\\KeyboardMacro");
    IoDeleteSymbolicLink(&SymbolicLink);
    IoDeleteDevice(DriverObject->DeviceObject);
}

}
usermode 
{

#include <windows.h>
#include <iostream>

#define IOCTL_SEND_KEY CTL_CODE(FILE_DEVICE_KEYBOARD, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _KEYBOARD_INPUT_DATA {
    USHORT MakeCode;
    USHORT Flags;
} KEYBOARD_INPUT_DATA, *PKEYBOARD_INPUT_DATA;

int main() {
    HANDLE hDevice = CreateFile(L"\\\\.\\KeyboardMacro",
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                NULL,
                                OPEN_EXISTING,
                                0,
                                NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device: " << GetLastError() << std::endl;
        return 1;
    }

    KEYBOARD_INPUT_DATA KeyData;
    KeyData.MakeCode = 0x1C; // Enter key
    KeyData.Flags = 0x00;    // KEY_MAKE

    DWORD bytesReturned;
    BOOL result = DeviceIoControl(hDevice,
                                  IOCTL_SEND_KEY,
                                  &KeyData,
                                  sizeof(KeyData),
                                  NULL,
                                  0,
                                  &bytesReturned,
                                  NULL);

    if (!result) {
        std::cerr << "DeviceIoControl failed: " << GetLastError() << std::endl;
    } else {
        std::cout << "Key sent successfully!" << std::endl;
    }

    CloseHandle(hDevice);
    return 0;
}

}