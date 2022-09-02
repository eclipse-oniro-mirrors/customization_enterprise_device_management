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

#define private public

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "enterprise_device_mgr_ability.h"
#include "plugin_manager_test.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
constexpr int32_t DEFAULT_USER_ID = 100;

class EnterpriseDeviceMgrAbilityTest : public testing::Test {
protected:
    // Sets up the test fixture.
    virtual void SetUp() override;

    // Tears down the test fixture.
    virtual void TearDown() override;
    sptr<EnterpriseDeviceMgrAbility> edmMgr_;
};

void EnterpriseDeviceMgrAbilityTest::SetUp()
{
    edmMgr_ = EnterpriseDeviceMgrAbility::GetInstance();
}

void EnterpriseDeviceMgrAbilityTest::TearDown()
{
    edmMgr_ = nullptr;
}

/**
 * @tc.name: TestHandleDevicePolicy
 * @tc.desc: Test EnterpriseDeviceMgrAbility::HandleDevicePolicy function.
 * @tc.type: FUNC
 * @tc.require: issueI5PBT1
 */
HWTEST_F(EnterpriseDeviceMgrAbilityTest, TestHandleDevicePolicy, TestSize.Level1)
{
    ErrCode res;
    AppExecFwk::ElementName elementName;
    elementName.SetBundleName("com.edm.test.demo");
    MessageParcel data;
    uint32_t code = POLICY_FUNC_CODE((std::uint32_t)FuncOperateType::SET, 0);

    edmMgr_->adminMgr_ = AdminManager::GetInstance();
    Admin testAdmin;
    testAdmin.adminInfo_.packageName_ = "com.edm.test.demo";
    testAdmin.adminInfo_.permission_ = {"ohos.permission.EDM_TEST_PERMISSION"};
    std::shared_ptr<Admin> adminPtr = std::make_shared<Admin>(testAdmin);
    std::vector<std::shared_ptr<Admin>> adminVec;
    adminVec.push_back(adminPtr);
    edmMgr_->adminMgr_->admins_
        .insert(std::pair<int32_t, std::vector<std::shared_ptr<Admin>>>(DEFAULT_USER_ID, adminVec));

    edmMgr_->pluginMgr_ = PluginManager::GetInstance();
    edmMgr_->pluginMgr_->AddPlugin(std::make_shared<TestPlugin>());
    res = edmMgr_->HandleDevicePolicy(code, elementName, data);
    ASSERT_TRUE(res == ERR_EDM_PERMISSION_ERROR);

    testAdmin.adminInfo_.permission_.clear();
    adminPtr = std::make_shared<Admin>(testAdmin);
    adminVec.clear();
    adminVec.push_back(adminPtr);
    edmMgr_->adminMgr_->admins_.clear();
    edmMgr_->adminMgr_->admins_
        .insert(std::pair<int32_t, std::vector<std::shared_ptr<Admin>>>(DEFAULT_USER_ID, adminVec));
    res = edmMgr_->HandleDevicePolicy(code, elementName, data);
    ASSERT_TRUE(res == ERR_EDM_PERMISSION_ERROR);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
