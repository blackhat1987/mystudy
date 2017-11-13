#include "stdafx.h"
#include "Driver.h"

/************************************************************************
* 函数名称:DriverEntry
* 功能描述:初始化驱动程序，定位和申请硬件资源，创建内核对象
* 参数列表:
pDriverObject:从I/O管理器中传进来的驱动对象
pRegistryPath:驱动程序在注册表的中的路径
* 返回 值:返回初始化驱动状态
*************************************************************************/
#pragma INITCODE
extern "C"
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  pDriverObject,_In_ PUNICODE_STRING RegistryPathName)
{
	UNREFERENCED_PARAMETER(RegistryPathName);
	NTSTATUS status = STATUS_SUCCESS;
	pDriverObject->DriverExtension->AddDevice = wdmAddDevice;	//这里创建设备
	pDriverObject->MajorFunction[IRP_MJ_PNP] = wdmPnp;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = commonDispatch;
	pDriverObject->MajorFunction[IRP_MJ_READ] = commonDispatch;
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = commonDispatch;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = commonDispatch;
	pDriverObject->DriverUnload = wdmUnload;
	
	DbgPrint("Driver load ok!\r\n", status);
	return status;
}

/************************************************************************
* 函数名称:HelloWDMAddDevice
* 功能描述:添加新设备
* 参数列表:
DriverObject:从I/O管理器中传进来的驱动对象
PhysicalDeviceObject:从I/O管理器中传进来的物理设备对象
* 返回 值:返回添加新设备状态
*************************************************************************/
#pragma PAGECODE
NTSTATUS wdmAddDevice(IN PDRIVER_OBJECT pDriverObj, IN PDEVICE_OBJECT PhysicalDeviceObject)
{
	PAGED_CODE();
	KdPrint(("Enter AddDevice"));

	NTSTATUS status;
	PDEVICE_OBJECT fdo;
	UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVICE_NAME);
	UNICODE_STRING symName = RTL_CONSTANT_STRING(LINK_NAME);

	status = IoCreateDevice(pDriverObj, sizeof(DEVICE_EXTENTION), &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &fdo);
	if (!NT_SUCCESS(status))
		return status;

	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)fdo->DeviceExtension;
	pdx->fdo = fdo;
	pdx->NextStackDevice = IoAttachDeviceToDeviceStack(fdo, PhysicalDeviceObject);
	pdx->ustrDeviceName = devName;
	pdx->ustrSymLickName = symName;
	
	status = IoCreateUnprotectedSymbolicLink(&symName, &devName);
	fdo->Flags |= DO_BUFFERED_IO | DO_POWER_PAGABLE;
	fdo->Flags &= ~DO_DEVICE_INITIALIZING;
	KdPrint(("Leave AddDevice"));
	return STATUS_SUCCESS;
}

/************************************************************************
* 函数名称:HelloWDMPnp
* 功能描述:对即插即用IRP进行处理
* 参数列表:
fdo:功能设备对象
Irp:从IO请求包
* 返回 值:返回状态
*************************************************************************/
NTSTATUS wdmPnp(IN PDEVICE_OBJECT fdo, IN PIRP irp)
{
#define arraysize(p) (sizeof(p) / sizeof((p)[0]))
	PAGED_CODE();

	KdPrint(("Enter HelloWDMPnp\n"));
	NTSTATUS status = STATUS_SUCCESS;
	PDEVICE_EXTENSION pdx = (PDEVICE_EXTENSION)fdo->DeviceExtension;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	static NTSTATUS(*fcntab[])(PDEVICE_EXTENSION pdx, PIRP irp) =
	{
		DefaultPnpHandler,		// IRP_MN_START_DEVICE
		DefaultPnpHandler,		// IRP_MN_QUERY_REMOVE_DEVICE
		HandleRemoveDevice,		// IRP_MN_REMOVE_DEVICE
		DefaultPnpHandler,		// IRP_MN_CANCEL_REMOVE_DEVICE
		DefaultPnpHandler,		// IRP_MN_STOP_DEVICE
		DefaultPnpHandler,		// IRP_MN_QUERY_STOP_DEVICE
		DefaultPnpHandler,		// IRP_MN_CANCEL_STOP_DEVICE
		DefaultPnpHandler,		// IRP_MN_QUERY_DEVICE_RELATIONS
		DefaultPnpHandler,		// IRP_MN_QUERY_INTERFACE
		DefaultPnpHandler,		// IRP_MN_QUERY_CAPABILITIES
		DefaultPnpHandler,		// IRP_MN_QUERY_RESOURCES
		DefaultPnpHandler,		// IRP_MN_QUERY_RESOURCE_REQUIREMENTS
		DefaultPnpHandler,		// IRP_MN_QUERY_DEVICE_TEXT
		DefaultPnpHandler,		// IRP_MN_FILTER_RESOURCE_REQUIREMENTS
		DefaultPnpHandler,		// 
		DefaultPnpHandler,		// IRP_MN_READ_CONFIG
		DefaultPnpHandler,		// IRP_MN_WRITE_CONFIG
		DefaultPnpHandler,		// IRP_MN_EJECT
		DefaultPnpHandler,		// IRP_MN_SET_LOCK
		DefaultPnpHandler,		// IRP_MN_QUERY_ID
		DefaultPnpHandler,		// IRP_MN_QUERY_PNP_DEVICE_STATE
		DefaultPnpHandler,		// IRP_MN_QUERY_BUS_INFORMATION
		DefaultPnpHandler,		// IRP_MN_DEVICE_USAGE_NOTIFICATION
		DefaultPnpHandler,		// IRP_MN_SURPRISE_REMOVAL
	};

	ULONG fcn = stack->MinorFunction;
	if (fcn >= arraysize(fcntab))
	{						// 未知的子功能代码
		status = DefaultPnpHandler(pdx, irp); // some function we don't know about
		return status;
	}

#if DBG
	static char* fcnname[] =
	{
		"IRP_MN_START_DEVICE",
		"IRP_MN_QUERY_REMOVE_DEVICE",
		"IRP_MN_REMOVE_DEVICE",
		"IRP_MN_CANCEL_REMOVE_DEVICE",
		"IRP_MN_STOP_DEVICE",
		"IRP_MN_QUERY_STOP_DEVICE",
		"IRP_MN_CANCEL_STOP_DEVICE",
		"IRP_MN_QUERY_DEVICE_RELATIONS",
		"IRP_MN_QUERY_INTERFACE",
		"IRP_MN_QUERY_CAPABILITIES",
		"IRP_MN_QUERY_RESOURCES",
		"IRP_MN_QUERY_RESOURCE_REQUIREMENTS",
		"IRP_MN_QUERY_DEVICE_TEXT",
		"IRP_MN_FILTER_RESOURCE_REQUIREMENTS",
		"",
		"IRP_MN_READ_CONFIG",
		"IRP_MN_WRITE_CONFIG",
		"IRP_MN_EJECT",
		"IRP_MN_SET_LOCK",
		"IRP_MN_QUERY_ID",
		"IRP_MN_QUERY_PNP_DEVICE_STATE",
		"IRP_MN_QUERY_BUS_INFORMATION",
		"IRP_MN_DEVICE_USAGE_NOTIFICATION",
		"IRP_MN_SURPRISE_REMOVAL",
	};

	KdPrint(("PNP Request (%s)\n", fcnname[fcn]));
#endif // DBG

	status = (*fcntab[fcn])(pdx, irp);
	KdPrint(("Leave HelloWDMPnp\n"));
	return status;
	return STATUS_SUCCESS;
}

#pragma PAGEDCODE
NTSTATUS DefaultPnpHandler(PDEVICE_EXTENSION pdx, PIRP Irp)
{
	PAGED_CODE();
	KdPrint(("Enter DefaultPnpHandler\n"));
	IoSkipCurrentIrpStackLocation(Irp);
	KdPrint(("Leave DefaultPnpHandler\n"));
	return IoCallDriver(pdx->NextStackDevice, Irp);
}

/************************************************************************
* 函数名称:HandleRemoveDevice
* 功能描述:对IRP_MN_REMOVE_DEVICE IRP进行处理
* 参数列表:
fdo:功能设备对象
Irp:从IO请求包
* 返回 值:返回状态
*************************************************************************/
#pragma PAGEDCODE
NTSTATUS HandleRemoveDevice(PDEVICE_EXTENSION pdx, PIRP Irp)
{
	PAGED_CODE();
	KdPrint(("Enter HandleRemoveDevice\n"));

	Irp->IoStatus.Status = STATUS_SUCCESS;
	NTSTATUS status = DefaultPnpHandler(pdx, Irp);
	IoDeleteSymbolicLink(&pdx->ustrSymLickName);

	//调用IoDetachDevice()把fdo从设备栈中脱开：
	if (pdx->NextStackDevice)
		IoDetachDevice(pdx->NextStackDevice);

	//删除fdo：
	IoDeleteDevice(pdx->fdo);
	KdPrint(("Leave HandleRemoveDevice\n"));
	return status;
}

NTSTATUS commonDispatch(IN PDEVICE_OBJECT fdo, IN PIRP irp) {
	PAGED_CODE();
	KdPrint(("Enter HelloWDMDispatchRoutine\n"));
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;	// no bytes xfered
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	KdPrint(("Leave HelloWDMDispatchRoutine\n"));
	return STATUS_SUCCESS;
}

void wdmUnload(IN PDRIVER_OBJECT pDriverObj)
{
	//do something when driver unload
	UNICODE_STRING ucLinkName = { 0 };
	RtlInitUnicodeString(&ucLinkName, LINK_NAME);
	IoDeleteSymbolicLink(&ucLinkName);
	IoDeleteDevice(pDriverObj->DeviceObject);
	DbgPrint("Driver unloaded\r\n");
}
