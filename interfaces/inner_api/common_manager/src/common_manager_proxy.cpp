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

#include "common_manager_proxy.h"

#include "edm_errors.h"
#include "edm_log.h"
#include "enterprise_device_mgr_proxy.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<CommonManagerProxy> CommonManagerProxy::instance_ = nullptr;
std::once_flag CommonManagerProxy::flag_;

std::shared_ptr<CommonManagerProxy> CommonManagerProxy::GetCommonManagerProxy()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_ = std::make_shared<CommonManagerProxy>();
        }
    });
    return instance_;
}

bool CommonManagerProxy::IsFeatureSupported(int32_t feature)
{
    EDMLOGI("CommonManagerProxy::IsFeatureSupported feature %{public}d", feature);
    sptr<IRemoteObject> remote = EnterpriseDeviceMgrProxy::GetInstance()->GetEdmRemoteObject();
    if (remote == nullptr) {
        EDMLOGE("CommonManagerProxy::IsFeatureSupported remote is null");
        return false;
    }
    sptr<IEnterpriseDeviceMgrIdl> mgrService = iface_cast<IEnterpriseDeviceMgrIdl>(remote);
    if (mgrService == nullptr) {
        EDMLOGE("CommonManagerProxy::IsFeatureSupported mgrService is null");
        return false;
    }
    bool supported = false;
    ErrCode ret = mgrService->IsFeatureSupported(feature, supported);
    if (FAILED(ret)) {
        EDMLOGE("CommonManagerProxy::IsFeatureSupported call fail. %{public}d", ret);
        return false;
    }
    return supported;
}
} // namespace EDM
} // namespace OHOS
