#pragma once
#include "stdafx.h"

//为避免混淆这两个要一致
#define  DEVICE_NAME L"\\device\\DrvWDMTemp"
#define  LINK_NAME   L"\\dosdevices\\DrvWDMTemp"

#define  PAGECODE code_seg("PAGE")
#define  LOCKEDCODE code_seg()
#define  INITCODE code_seg("INIT")
#define PAGEDATA data_seg("PAGE")
#define LOCKEDDATA data_seg()
#define INITDATA data_seg("INIT")

#define IOCTRL_BASE 0X8000
#define FGIOCTRL_CODE(i) \
	CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE + i, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_SEND_RESULT_TO_R0 FGIOCTRL_CODE(0)
#define IOCTL_XXX_ATTACK        FGIOCTRL_CODE(1)

typedef struct _DEVICE_EXTENSION 
{
	PDEVICE_OBJECT fdo;
	PDEVICE_OBJECT NextStackDevice;
	UNICODE_STRING ustrDeviceName;
	UNICODE_STRING ustrSymLickName;
}DEVICE_EXTENTION, *PDEVICE_EXTENSION;

extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  pDriverObject, _In_ PUNICODE_STRING RegistryPathName);
NTSTATUS commonDispatch(IN PDEVICE_OBJECT fdo, IN PIRP irp);
void wdmUnload(IN PDRIVER_OBJECT pDriverObj);

NTSTATUS wdmAddDevice(IN PDRIVER_OBJECT pDriverObj, IN PDEVICE_OBJECT PhysicalDeviceObject);
NTSTATUS wdmPnp(IN PDEVICE_OBJECT fdo, IN PIRP irp);
NTSTATUS DefaultPnpHandler(PDEVICE_EXTENSION pdx, PIRP Irp);
NTSTATUS HandleRemoveDevice(PDEVICE_EXTENSION pdx, PIRP Irp);





