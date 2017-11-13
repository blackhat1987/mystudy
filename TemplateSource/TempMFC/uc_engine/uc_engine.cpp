#include "stdafx.h"
#include "uc_engine.h"

namespace usr::ucengine
{
	void hook_fetch_memory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
	{
		auto _this = reinterpret_cast<uc_engine_base*>(user_data);
		if (_this)
		{
			_this->on_fetch(type, address, size, value);
		}
	}
	void hook_unmap_memory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
	{
		auto _this = reinterpret_cast<uc_engine_base*>(user_data);
		if (_this)
		{
			_this->on_umap(type, address, size, value);
		}
	}
};