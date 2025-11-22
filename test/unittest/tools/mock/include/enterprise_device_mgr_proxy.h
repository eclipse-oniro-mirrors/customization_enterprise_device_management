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

#ifndef EDM_UNIT_TEST_TOOLS_MOCK_INCLUDE_ENTERPRISE_DEVICE_MGR_PROXY_H
#define EDM_UNIT_TEST_TOOLS_MOCK_INCLUDE_ENTERPRISE_DEVICE_MGR_PROXY_H

#include <message_parcel.h>

#include <memory>

#include "admin_type.h"
#include "edm_errors.h"
#include "element_name.h"
#include "ent_info.h"

namespace OHOS {
namespace EDM {
constexpr int32_t DEFAULT_USER_ID = 100;

class EnterpriseDeviceMgrProxy {
public:
    static std::shared_ptr<EnterpriseDeviceMgrProxy> GetInstance();

    ErrCode EnableAdmin(AppExecFwk::ElementName &admin, EntInfo &entInfo, AdminType type, int32_t userId);
    ErrCode DisableAdmin(AppExecFwk::ElementName &admin, int32_t userId);

private:
    static std::shared_ptr<EnterpriseDeviceMgrProxy> instance_;
};
} // namespace EDM
} // namespace OHOS

#endif // EDM_UNIT_TEST_TOOLS_MOCK_INCLUDE_ENTERPRISE_DEVICE_MGR_PROXY_H
