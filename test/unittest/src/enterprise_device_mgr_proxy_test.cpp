/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "cmd_utils.h"
#include "enterprise_device_mgr_proxy.h"
#include "func_code.h"
#include "policy_info.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t DEFAULT_USERID = 100;
class EnterpriseDeviceMgrProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<EnterpriseDeviceMgrProxy> enterpriseDeviceMgrProxyTest;
};

void EnterpriseDeviceMgrProxyTest::SetUp()
{
    enterpriseDeviceMgrProxyTest = EnterpriseDeviceMgrProxy::GetInstance();
}

void EnterpriseDeviceMgrProxyTest::TearDown()
{
    EnterpriseDeviceMgrProxy::DestroyInstance();
}

/**
 * @tc.name: TestDisableAdmin
 * @tc.desc: Test DisableAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestDisableAdmin, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");

    EntInfo entInfo("test", "this is test");

    ErrCode errVal = enterpriseDeviceMgrProxyTest->EnableAdmin(admin, entInfo, AdminType::NORMAL, DEFAULT_USERID);
    EXPECT_TRUE(errVal != ERR_OK);

    errVal = enterpriseDeviceMgrProxyTest->SetEnterpriseInfo(admin, entInfo);
    EXPECT_TRUE(errVal != ERR_OK);

    EntInfo entInfo1;
    enterpriseDeviceMgrProxyTest->GetEnterpriseInfo(admin, entInfo1);
    EXPECT_TRUE(entInfo1.enterpriseName.size() == 0);
    EXPECT_TRUE(entInfo1.description.size() == 0);

    bool ret = enterpriseDeviceMgrProxyTest->IsAdminEnabled(admin, DEFAULT_USERID);
    EXPECT_FALSE(ret);


    std::vector<std::string> enabledAdminList;
    enterpriseDeviceMgrProxyTest->GetEnabledAdmins(enabledAdminList);
    EXPECT_TRUE(enabledAdminList.empty());

    std::vector<std::u16string> enabledAdminList1;
    enterpriseDeviceMgrProxyTest->GetEnabledAdmin(AdminType::NORMAL, enabledAdminList1);
    EXPECT_TRUE(enabledAdminList1.empty());

    int funcCode = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, SET_DATETIME);
    bool isDisabled;
    enterpriseDeviceMgrProxyTest->IsPolicyDisable(funcCode, isDisabled);
    EXPECT_FALSE(isDisabled);


    errVal = enterpriseDeviceMgrProxyTest->DisableAdmin(admin, DEFAULT_USERID);
    EXPECT_TRUE(errVal != ERR_OK);
}

/**
 * @tc.name: TestDisableSuperAdmin
 * @tc.desc: Test DisableSuperAdmin func.
 * @tc.type: FUNC
 */
HWTEST_F(EnterpriseDeviceMgrProxyTest, TestDisableSuperAdmin, TestSize.Level1)
{
    AppExecFwk::ElementName admin;
    admin.SetBundleName("com.edm.test.demo");
    admin.SetAbilityName("com.edm.test.demo.Ability");

    EntInfo entInfo("test", "this is test");

    ErrCode errVal = enterpriseDeviceMgrProxyTest->EnableAdmin(admin, entInfo, AdminType::ENT, DEFAULT_USERID);
    EXPECT_TRUE(errVal != ERR_OK);

    bool ret = enterpriseDeviceMgrProxyTest->IsSuperAdmin("com.edm.test.demo");
    EXPECT_FALSE(ret);

    std::string enabledAdmin;
    enterpriseDeviceMgrProxyTest->GetEnabledSuperAdmin(enabledAdmin);
    EXPECT_TRUE(enabledAdmin.size() == 0);

    ret = enterpriseDeviceMgrProxyTest->IsSuperAdminExist();
    EXPECT_FALSE(ret);

    errVal = enterpriseDeviceMgrProxyTest->DisableSuperAdmin("com.edm.test.demo");
    EXPECT_TRUE(errVal != ERR_OK);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
