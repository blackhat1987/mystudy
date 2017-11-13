#include "stdafx.h"
#include "ioctrl.h"

extern ddk::nt_device device;	//参数来自于Main.cpp
NTSTATUS Ioctrl_Handle1(PVOID InputBuffer,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	ULONG_PTR *ReturnSize)
{
	LOG_DEBUG("控制码800\r\n");
	*ReturnSize = 0;
	return STATUS_SUCCESS;
}

NTSTATUS Ioctrl_Handle2(PVOID InputBuffer,
	ULONG InputBufferSize,
	PVOID OutputBuffer,
	ULONG OutputBufferSize,
	ULONG_PTR *ReturnSize, 
	int xxx)
{
	DbgPrint("hello world %x\r\n", xxx);
	*ReturnSize = 0;
	return STATUS_SUCCESS;
}

NTSTATUS CreateDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	LOG_DEBUG("create dispatch\r\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS ReadDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	
	LOG_DEBUG("read dispatch\r\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS WriteDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	LOG_DEBUG("write dispatch\r\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CloseDispatch(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	LOG_DEBUG("close dispatch\r\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void setDpcFun()
{
	//read, wirte
	device.set_irp_callback(IRP_MJ_CREATE, CreateDispatch);
	device.set_irp_callback(IRP_MJ_READ, ReadDispatch);
	device.set_irp_callback(IRP_MJ_WRITE, WriteDispatch);
	device.set_irp_callback(IRP_MJ_CLOSE, CloseDispatch);


	//ioctl
	device.set_ioctrl_callback(FG_IOCTL_HELLO, Ioctrl_Handle1);
	auto bind_fun = std::bind(&Ioctrl_Handle2, std::placeholders::_1, std::placeholders::_2,
		std::placeholders::_3, std::placeholders::_4, std::placeholders::_5, 0x123456);
	device.set_ioctrl_callback(FG_IOCTL_HELLO2, bind_fun);	//可以使用bind
}