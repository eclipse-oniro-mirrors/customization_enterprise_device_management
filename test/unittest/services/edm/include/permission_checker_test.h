/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef EDM_UNIT_TEST_ENTERPRISE_DEVICE_MGR_ABILITY_TEST_H
#define EDM_UNIT_TEST_ENTERPRISE_DEVICE_MGR_ABILITY_TEST_H

#include <gtest/gtest.h>
#include <memory>

#define private public
#include "permission_checker.h"
#undef private

#include "edm_access_token_manager_impl_mock.h"
#include "edm_app_manager_impl_mock.h"
#include "edm_bundle_manager_impl_mock.h"
#include "edm_os_account_manager_impl_mock.h"
#include "enterprise_device_mgr_ability_mock.h"
#include "external_manager_factory_mock.h"
#include "permission_checker_mock.h"

namespace OHOS {
namespace EDM {
namespace TEST {
class PermissionCheckerTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
   
protected:
    std::shared_ptr<EdmAppManagerImplMock> appMgrMock_ = nullptr;
    std::shared_ptr<EdmBundleManagerImplMock> bundleMgrMock_ = nullptr;
    std::shared_ptr<EdmOsAccountManagerImplMock> osAccountMgrMock_ = nullptr;
    std::shared_ptr<EdmAccessTokenManagerImplMock> accessTokenMgrMock_ = nullptr;
    std::shared_ptr<ExternalManagerFactoryMock> factoryMock_ = nullptr;
    std::shared_ptr<PermissionCheckerMock> permissionChecker_ = nullptr;
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_ENTERPRISE_DEVICE_MGR_ABILITY_TEST_H