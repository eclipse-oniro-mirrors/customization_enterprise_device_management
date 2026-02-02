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

#ifndef TEST_UNITTEST_SERVICES_EDM_INCLUDE_UPDATE_POLICY_CONFLICT_TEST_H
#define TEST_UNITTEST_SERVICES_EDM_INCLUDE_UPDATE_POLICY_CONFLICT_TEST_H

#include <gtest/gtest.h>

#include "edm_access_token_manager_impl_mock.h"
#include "edm_bundle_manager_impl_mock.h"
#include "edm_os_account_manager_impl_mock.h"
#include "enterprise_device_mgr_ability_mock.h"
#include "external_manager_factory_mock.h"
#include "permission_checker_mock.h"
#include "update_policy_info.h"

namespace OHOS {
namespace EDM {
namespace TEST {
enum TestMethod {
    SET_UPDATE_POLICY,
    NOTIFY_UPDATE_POLICY
};

struct UpdatePolicyTestParam {
    AdminType adminType1 = AdminType::UNKNOWN;
    AdminType adminType2 = AdminType::UNKNOWN;
    UpdatePolicyType updatePolicyType = UpdatePolicyType::DEFAULT;
    TestMethod testMethod = TestMethod::SET_UPDATE_POLICY;
    ErrCode expectedRet = ERR_INVALID_VALUE;
    bool isNotifyPackages = false;
    UpdatePolicyTestParam(AdminType type1, UpdatePolicyType policyType, bool isNotify, AdminType type2,
        TestMethod method, ErrCode ret) : adminType1(type1), adminType2(type2), updatePolicyType(policyType),
        testMethod(method), expectedRet(ret), isNotifyPackages(isNotify) {}
};

class UpdatePolicyConflictTest : public testing::TestWithParam<UpdatePolicyTestParam> {
public:
    void SetUp() override;
    void TearDown() override;
    static void SetUpTestSuite();
    static void TearDownTestSuite();

    AdminInfo CreateAdminInfo(AdminType adminType, const std::string &bundleName);
    void TestSetUpdatePolicy(std::shared_ptr<Admin> admin, UpdatePolicyType updatePolicyType, ErrCode expectedRet);
    void TestNotifyUpgradePackages(std::shared_ptr<Admin> admin, ErrCode expectedRet);

protected:
    sptr<EnterpriseDeviceMgrAbilityMock> edmMgr_ = nullptr;
    std::shared_ptr<EdmBundleManagerImplMock> bundleMgrMock_ = nullptr;
    std::shared_ptr<EdmOsAccountManagerImplMock> osAccountMgrMock_ = nullptr;
    std::shared_ptr<EdmAccessTokenManagerImplMock> accessTokenMgrMock_ = nullptr;
    std::shared_ptr<ExternalManagerFactoryMock> factoryMock_ = nullptr;
    std::shared_ptr<PermissionCheckerMock> permissionCheckerMock_ = nullptr;
};
} // namespace TEST
} // namespace EDM
} // namespace OHOS
#endif // TEST_UNITTEST_SERVICES_EDM_INCLUDE_UPDATE_POLICY_CONFLICT_TEST_H