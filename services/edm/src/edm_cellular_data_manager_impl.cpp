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

#include "edm_cellular_data_manager_impl.h"

#include "cellular_data_client.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::shared_ptr<EdmCellularDataManagerImpl> EdmCellularDataManagerImpl::instance_;
std::once_flag EdmCellularDataManagerImpl::flag_;

std::shared_ptr<EdmCellularDataManagerImpl> EdmCellularDataManagerImpl::GetInstance()
{
    std::call_once(flag_, []() {
        if (instance_ == nullptr) {
            instance_.reset(new (std::nothrow) EdmCellularDataManagerImpl());
        }
    });
    IEdmCellularDataManager::iInstance_ = instance_.get();
    return instance_;
}

int32_t EdmCellularDataManagerImpl::EnableCellularData(bool enable)
{
    EDMLOGI("EdmCellularDataManagerImpl::EnableCellularData enable=%{public}d", enable);
    int32_t ret = Telephony::CellularDataClient::GetInstance().EnableCellularData(enable);
    EDMLOGI("EdmCellularDataManagerImpl::EnableCellularData enable=%{public}d, ret=%{public}d", enable, ret);
    return ret;
}
} // namespace EDM
} // namespace OHOS
