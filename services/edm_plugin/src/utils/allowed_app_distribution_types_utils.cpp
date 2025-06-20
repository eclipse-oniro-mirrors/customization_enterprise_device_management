/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "allowed_app_distribution_types_utils.h"

#include <system_ability_definition.h>

#include "app_distribution_type.h"
#include "edm_log.h"
#include "edm_sys_manager.h"

namespace OHOS {
namespace EDM {
ErrCode AllowedAppDistributionTypesUtils::SetAppDistributionTypes(std::vector<int32_t> data)
{
    EDMLOGI("AllowedAppDistributionTypesUtils SetAppDistributionTypes....data size = %{public}zu", data.size());
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (proxy == nullptr) {
        EDMLOGE("sptr<AppExecFwk::IBundleMgr> proxy is null");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::set<AppExecFwk::AppDistributionTypeEnum> appDistributionTypeEnum;
    for (const auto &item : data) {
        switch (item) {
            case static_cast<int32_t>(AppDistributionType::APP_GALLERY):
                appDistributionTypeEnum.insert(AppExecFwk::AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_APP_GALLERY);
                break;
            case static_cast<int32_t>(AppDistributionType::ENTERPRISE):
                appDistributionTypeEnum.insert(AppExecFwk::AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_ENTERPRISE);
                break;
            case static_cast<int32_t>(AppDistributionType::ENTERPRISE_NORMAL):
                appDistributionTypeEnum.insert(
                    AppExecFwk::AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_ENTERPRISE_NORMAL);
                break;
            case static_cast<int32_t>(AppDistributionType::ENTERPRISE_MDM):
                appDistributionTypeEnum.insert(
                    AppExecFwk::AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_ENTERPRISE_MDM);
                break;
            case static_cast<int32_t>(AppDistributionType::INTERNALTESTING):
                appDistributionTypeEnum.insert(
                    AppExecFwk::AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_INTERNALTESTING);
                break;
            case static_cast<int32_t>(AppDistributionType::CROWDTESTING):
                appDistributionTypeEnum.insert(
                    AppExecFwk::AppDistributionTypeEnum::APP_DISTRIBUTION_TYPE_CROWDTESTING);
                break;
            default:
                break;
        }
    }
    ErrCode ret = proxy->SetAppDistributionTypes(appDistributionTypeEnum);
    if (ret != ERR_OK) {
        EDMLOGE("AllowedAppDistributionTypesUtils SetAppDistributionTypes ret %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
}
}