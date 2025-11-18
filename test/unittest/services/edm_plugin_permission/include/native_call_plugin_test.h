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

#ifndef EDM_UNIT_TEST_SERVICES_EDM_PLUGIN_PERMISSION_NATIVE_CALL_PLUGIN_TEST_H
#define EDM_UNIT_TEST_SERVICES_EDM_PLUGIN_PERMISSION_NATIVE_CALL_PLUGIN_TEST_H

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "edm_app_manager_impl_mock.h"
#include "edm_bundle_manager_impl_mock.h"
#include "edm_os_account_manager_impl_mock.h"
#include "enterprise_device_mgr_ability_mock.h"
#include "external_manager_factory_mock.h"
#include "permission_checker_mock.h"
#include "test_param.h"

namespace OHOS {
namespace EDM {
namespace TEST {
class NativeCallPluginTest : public testing::TestWithParam<TestParam> {
public:
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<EnterpriseDeviceMgrAbilityMock> edmMgr_ = std::make_shared<EnterpriseDeviceMgrAbilityMock>();
    std::shared_ptr<EdmAppManagerImplMock> appMgrMock_ = std::make_shared<EdmAppManagerImplMock>();
    std::shared_ptr<EdmBundleManagerImplMock> bundleMgrMock_ = std::make_shared<EdmBundleManagerImplMock>();
    std::shared_ptr<EdmOsAccountManagerImplMock> osAccountMgrMock_ = std::make_shared<EdmOsAccountManagerImplMock>();
    std::shared_ptr<EdmAccessTokenManagerImpl> accessTokenMgr_ = std::make_shared<EdmAccessTokenManagerImpl>();
    std::shared_ptr<ExternalManagerFactoryMock> factoryMock_ = std::make_shared<ExternalManagerFactoryMock>();
    std::shared_ptr<PermissionCheckerMock> permissionCheckerMock_ = std::make_shared<PermissionCheckerMock>();
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_SERVICES_EDM_PLUGIN_PERMISSION_NATIVE_CALL_PLUGIN_TEST_H