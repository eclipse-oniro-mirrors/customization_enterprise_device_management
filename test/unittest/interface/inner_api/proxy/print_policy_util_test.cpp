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
 
#include <gtest/gtest.h>
 
#include <string>
#include <vector>
 
#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_proxy.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "func_code.h"
#include "print_policy_util.h"
#include "system_ability_definition.h"
#include "utils.h"
 
using namespace testing::ext;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Mock;
using namespace testing;
 
namespace OHOS {
namespace EDM {
namespace TEST {
namespace {
constexpr int32_t TEST_USER_ID = 100;
const std::u16string DESCRIPTOR = u"ohos.edm.IEnterpriseDeviceMgr";
}
 
class PrintPolicyUtilTest : public testing::Test {
protected:
    void SetUp() override;
 
    void TearDown() override;
 
    static void TearDownTestSuite(void);
 
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};
 
void PrintPolicyUtilTest::SetUp()
{
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}
 
void PrintPolicyUtilTest::TearDown()
{
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}
 
void PrintPolicyUtilTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
}
 
/**
 * @tc.name: TestGetPrintPolicy_EdmDisabled
 * @tc.desc: Test GetPrintPolicy when EDM is not enabled.
 * @tc.type: FUNC
 */
HWTEST_F(PrintPolicyUtilTest, TestGetPrintPolicy_EdmDisabled, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    std::string json;
    ErrCode ret = PrintPolicyUtil::GetPrintPolicy(TEST_USER_ID, json);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(json, "{}");
}
 
/**
 * @tc.name: TestGetPrintPolicy_DeviceLevelOnly
 * @tc.desc: Test GetPrintPolicy with only device-level policy set.
 * @tc.type: FUNC
 */
HWTEST_F(PrintPolicyUtilTest, TestGetPrintPolicy_DeviceLevelOnly, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            reply.WriteInt32(ERR_OK);
            std::vector<std::string> ips = {"192.168.1.1", "10.0.0.1"};
            reply.WriteStringVector(ips);
            return 0;
        }));
 
    std::string json;
    ErrCode ret = PrintPolicyUtil::GetPrintPolicy(TEST_USER_ID, json);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_NE(json.find("printer_policies"), std::string::npos);
    ASSERT_NE(json.find("192.168.1.1"), std::string::npos);
}
 
/**
 * @tc.name: TestGetPrintPolicy_UserLevelFallback
 * @tc.desc: Test GetPrintPolicy falling back to user-level when device-level is empty.
 * @tc.type: FUNC
 */
HWTEST_F(PrintPolicyUtilTest, TestGetPrintPolicy_UserLevelFallback, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            // First call: device-level query returns empty
            reply.WriteInt32(ERR_OK);
            reply.WriteStringVector({});
            return 0;
        }))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            // Second call: user-level query returns data
            reply.WriteInt32(ERR_OK);
            std::vector<std::string> ips = {"172.16.0.1"};
            reply.WriteStringVector(ips);
            return 0;
        }));
 
    std::string json;
    ErrCode ret = PrintPolicyUtil::GetPrintPolicy(TEST_USER_ID, json);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_NE(json.find("printer_policies"), std::string::npos);
    ASSERT_NE(json.find("172.16.0.1"), std::string::npos);
}
 
/**
 * @tc.name: TestGetPrintPolicy_BothEmpty
 * @tc.desc: Test GetPrintPolicy when both device and user level policies are empty.
 * @tc.type: FUNC
 */
HWTEST_F(PrintPolicyUtilTest, TestGetPrintPolicy_BothEmpty, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            reply.WriteInt32(ERR_OK);
            reply.WriteStringVector({});
            return 0;
        }))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            reply.WriteInt32(ERR_OK);
            reply.WriteStringVector({});
            return 0;
        }));
 
    std::string json;
    ErrCode ret = PrintPolicyUtil::GetPrintPolicy(TEST_USER_ID, json);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(json, "{}");
}
 
/**
 * @tc.name: TestGetPrintPolicy_BuildJson
 * @tc.desc: Test GetPrintPolicy JSON assembly format.
 * @tc.type: FUNC
 */
HWTEST_F(PrintPolicyUtilTest, TestGetPrintPolicy_BuildJson, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            reply.WriteInt32(ERR_OK);
            std::vector<std::string> ips = {"192.168.1.1"};
            reply.WriteStringVector(ips);
            return 0;
        }));
 
    std::string json;
    ErrCode ret = PrintPolicyUtil::GetPrintPolicy(TEST_USER_ID, json);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_EQ(json, "{\"printer_policies\":[{\"device_ip\":\"192.168.1.1\"}]}");
}
 
/**
 * @tc.name: TestGetPrintPolicy_DeviceQueryFails
 * @tc.desc: Test GetPrintPolicy when device-level query fails, fallback to user-level.
 * @tc.type: FUNC
 */
HWTEST_F(PrintPolicyUtilTest, TestGetPrintPolicy_DeviceQueryFails, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            // Device-level query fails
            reply.WriteInt32(ERR_INVALID_VALUE);
            return 0;
        }))
        .WillOnce(Invoke([](uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) {
            // User-level fallback succeeds
            reply.WriteInt32(ERR_OK);
            std::vector<std::string> ips = {"10.0.0.1"};
            reply.WriteStringVector(ips);
            return 0;
        }));
 
    std::string json;
    ErrCode ret = PrintPolicyUtil::GetPrintPolicy(TEST_USER_ID, json);
    ASSERT_EQ(ret, ERR_OK);
    ASSERT_NE(json.find("10.0.0.1"), std::string::npos);
}
 
} // namespace TEST
} // namespace EDM
} // namespace OHOS