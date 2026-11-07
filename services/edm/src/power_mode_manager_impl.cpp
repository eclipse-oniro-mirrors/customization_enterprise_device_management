/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "power_mode_manager_impl.h"

#include <new>

#include "edm_log.h"
#include "power_mgr_client.h"
#include "power_mode_info.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<PowerModeManagerImpl> PowerModeManagerImpl::instance_;
std::once_flag PowerModeManagerImpl::flag_;

std::shared_ptr<PowerModeManagerImpl> PowerModeManagerImpl::GetInstance()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) PowerModeManagerImpl());
        }
    });
    IPowerModeManager::iInstance_ = instance_.get();
    return instance_;
}

uint32_t PowerModeManagerImpl::GetDeviceMode()
{
    auto& powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
    return static_cast<uint32_t>(powerMgrClient.GetDeviceMode());
}

ErrCode PowerModeManagerImpl::SetDeviceMode(uint32_t mode)
{
    auto& powerMgrClient = PowerMgr::PowerMgrClient::GetInstance();
    PowerMgr::PowerErrors ret = powerMgrClient.SetDeviceMode(static_cast<PowerMgr::PowerMode>(mode));
    if (ret != PowerMgr::PowerErrors::ERR_OK) {
        EDMLOGE("PowerModeManagerImpl SetDeviceMode failed, error: %{public}d", int32_t(ret));
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
