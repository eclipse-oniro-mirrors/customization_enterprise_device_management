/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "permission_checker.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"

namespace OHOS {
namespace EDM {
std::vector<uint32_t> PermissionChecker::supportAdminNullPolicyCode_ = {
    EdmInterfaceCode::DISALLOW_ADD_OS_ACCOUNT_BY_USER,
    EdmInterfaceCode::DISALLOW_ADD_LOCAL_ACCOUNT,
    EdmInterfaceCode::DISABLE_BLUETOOTH,
    EdmInterfaceCode::ALLOWED_BLUETOOTH_DEVICES,
    EdmInterfaceCode::SET_BROWSER_POLICIES,
    EdmInterfaceCode::DISALLOW_MODIFY_DATETIME,
    EdmInterfaceCode::LOCATION_POLICY,
    EdmInterfaceCode::FINGERPRINT_AUTH,
    EdmInterfaceCode::DISABLE_MICROPHONE,
    EdmInterfaceCode::DISABLED_PRINTER,
    EdmInterfaceCode::DISABLED_HDC,
    EdmInterfaceCode::DISABLE_USB,
    EdmInterfaceCode::DISALLOWED_USB_DEVICES,
    EdmInterfaceCode::USB_READ_ONLY,
    EdmInterfaceCode::ALLOWED_USB_DEVICES,
    EdmInterfaceCode::DISABLE_WIFI,
    EdmInterfaceCode::DISABLE_CAMERA,
    EdmInterfaceCode::PASSWORD_POLICY,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISALLOW_SCREEN_SHOT,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISALLOW_SCREEN_RECORD,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_DISK_RECOVERY_KEY,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISALLOW_NEAR_LINK,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_DEVELOPER_MODE,
    EdmInterfaceCode::POLICY_CODE_END + EdmConstants::PolicyCode::DISABLE_RESET_FACTORY
};

std::vector<uint32_t> PermissionChecker::getSupportAdminNullPolicyCode()
{
    return supportAdminNullPolicyCode_;
}
} // namespace EDM
} // namespace OHOS
