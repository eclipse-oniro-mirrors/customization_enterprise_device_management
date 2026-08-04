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

#ifndef SERVICES_EDM_INCLUDE_EDM_CELLULAR_DATA_MANAGER_IMPL_H
#define SERVICES_EDM_INCLUDE_EDM_CELLULAR_DATA_MANAGER_IMPL_H

#include <memory>
#include <mutex>

#include "iedm_cellular_data_manager.h"

namespace OHOS {
namespace EDM {
class EdmCellularDataManagerImpl : public IEdmCellularDataManager {
public:
    static std::shared_ptr<EdmCellularDataManagerImpl> GetInstance();
    ~EdmCellularDataManagerImpl() override = default;
    int32_t EnableCellularData(bool enable) override;

private:
    EdmCellularDataManagerImpl() = default;
    static std::once_flag flag_;
    static std::shared_ptr<EdmCellularDataManagerImpl> instance_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_CELLULAR_DATA_MANAGER_IMPL_H
