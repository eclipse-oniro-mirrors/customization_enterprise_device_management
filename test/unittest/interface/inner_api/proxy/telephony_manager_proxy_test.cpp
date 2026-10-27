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

#include "telephony_manager_proxy.h"

#include <gtest/gtest.h>
#include <system_ability_definition.h>

#include <string>
#include <vector>

#include "edm_sys_manager_mock.h"
#include "enterprise_device_mgr_stub_mock.h"
#include "sms_message_info.h"
#include "utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
const std::string ADMIN_PACKAGENAME = "com.edm.test.demo";
class TelephonyManagerProxyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    static void TearDownTestSuite(void);
    std::shared_ptr<TelephonyManagerProxy> telephonyManagerProxy = nullptr;
    std::shared_ptr<EdmSysManager> edmSysManager_ = nullptr;
    sptr<EnterpriseDeviceMgrStubMock> object_ = nullptr;
};

void TelephonyManagerProxyTest::SetUp()
{
    telephonyManagerProxy = TelephonyManagerProxy::GetTelephonyManagerProxy();
    edmSysManager_ = std::make_shared<EdmSysManager>();
    object_ = new (std::nothrow) EnterpriseDeviceMgrStubMock();
    edmSysManager_->RegisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID, object_);
    Utils::SetEdmServiceEnable();
}

void TelephonyManagerProxyTest::TearDown()
{
    telephonyManagerProxy.reset();
    edmSysManager_->UnregisterSystemAbilityOfRemoteObject(ENTERPRISE_DEVICE_MANAGER_SA_ID);
    object_ = nullptr;
    Utils::SetEdmServiceDisable();
}

void TelephonyManagerProxyTest::TearDownTestSuite()
{
    ASSERT_FALSE(Utils::GetEdmServiceState());
    std::cout << "EdmServiceState : " << Utils::GetEdmServiceState() << std::endl;
}

/**
 * @tc.name: TestSetSimDisabledSuc
 * @tc.desc: Test SetSimDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestSetSimDisabledSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(0);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = telephonyManagerProxy->SetSimDisabled(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetSimDisabledFail
 * @tc.desc: Test SetSimDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestSetSimDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(0);
    int32_t ret = telephonyManagerProxy->SetSimDisabled(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetSimEnabledSuc
 * @tc.desc: Test SetSimEnabled func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestSetSimEnabledSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(0);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));

    int32_t ret = telephonyManagerProxy->SetSimEnabled(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetSimEnabledFail
 * @tc.desc: Test SetSimEnabled func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestSetSimEnabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(0);
    int32_t ret = telephonyManagerProxy->SetSimEnabled(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestIsSimDisabledSuc
 * @tc.desc: Test IsSimDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestIsSimDisabledSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(0);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    bool result = false;
    int32_t ret = telephonyManagerProxy->IsSimDisabled(data, result);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestIsSimDisabledFail
 * @tc.desc: Test IsSimDisabled func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestIsSimDisabledFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    data.WriteInt32(0);
    bool result = false;
    int32_t ret = telephonyManagerProxy->IsSimDisabled(data, result);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_FALSE(result);
}

/**
 * @tc.name: TestAddCallPolicyNumbersSuc
 * @tc.desc: Test AddCallPolicyNumbers func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestAddCallPolicyNumbersSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string callType = "incoming";
    int32_t policyFlag = 0;
    std::vector<std::string> numbers;
    numbers.push_back("1111111");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = telephonyManagerProxy->AddCallPolicyNumbers(admin, callType, policyFlag, numbers);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestAddCallPolicyNumbersFail
 * @tc.desc: Test AddCallPolicyNumbers func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestAddCallPolicyNumbersFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string callType = "incoming";
    int32_t policyFlag = 0;
    std::vector<std::string> numbers;
    numbers.push_back("1111111");
    int32_t ret = telephonyManagerProxy->AddCallPolicyNumbers(admin, callType, policyFlag, numbers);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestRemoveCallPolicyNumbersSuc
 * @tc.desc: Test RemoveCallPolicyNumbers func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestRemoveCallPolicyNumbersSuc, TestSize.Level1)
{
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string callType = "incoming";
    int32_t policyFlag = 0;
    std::vector<std::string> numbers;
    numbers.push_back("1111111");
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = telephonyManagerProxy->RemoveCallPolicyNumbers(admin, callType, policyFlag, numbers);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestRemoveCallPolicyNumbersFail
 * @tc.desc: Test RemoveCallPolicyNumbers func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestRemoveCallPolicyNumbersFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    std::string callType = "incoming";
    int32_t policyFlag = 0;
    std::vector<std::string> numbers;
    numbers.push_back("1111111");
    int32_t ret = telephonyManagerProxy->RemoveCallPolicyNumbers(admin, callType, policyFlag, numbers);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetCallPolicyNumbersSuc
 * @tc.desc: Test GetCallPolicyNumbers func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetCallPolicyNumbersSuc, TestSize.Level1)
{
    MessageParcel data;
    std::vector<std::string> numbers;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
    .Times(1)
    .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = telephonyManagerProxy->GetCallPolicyNumbers(data, numbers);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetCallPolicyNumbersFail
 * @tc.desc: Test GetCallPolicyNumbers func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetCallPolicyNumbersFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    std::vector<std::string> numbers;
    int32_t ret = telephonyManagerProxy->GetCallPolicyNumbers(data, numbers);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestHangupCallingSuc
 * @tc.desc: Test HangupCalling success func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestHangupCallingSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = telephonyManagerProxy->HangupCalling(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestHangupCallingFail
 * @tc.desc: Test HangupCalling without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestHangupCallingFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    int32_t ret = telephonyManagerProxy->HangupCalling(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestActiveSimSuc
 * @tc.desc: Test active sim success func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestActiveSimSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = telephonyManagerProxy->ActiveSim(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestActiveSimFail
 * @tc.desc: Test active sim without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestActiveSimFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    int32_t ret = telephonyManagerProxy->ActiveSim(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestDeactiveSimSuc
 * @tc.desc: Test deactive sim success func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestDeactiveSimSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = telephonyManagerProxy->DeactiveSim(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestDeactiveSimFail
 * @tc.desc: Test deactive sim without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestDeactiveSimFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    int32_t ret = telephonyManagerProxy->DeactiveSim(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestSetDefaultDataSimSuc
 * @tc.desc: Test SetDefaultDataSim success func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestSetDefaultDataSimSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = telephonyManagerProxy->SetDefaultDataSim(data);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestSetDefaultDataSimFail
 * @tc.desc: Test SetDefaultDataSim without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestSetDefaultDataSimFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    int32_t ret = telephonyManagerProxy->SetDefaultDataSim(data);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetDefaultDataSimSuc
 * @tc.desc: Test GetDefaultDataSim success func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetDefaultDataSimSuc, TestSize.Level1)
{
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    int32_t simId = -1;
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy));
    int32_t ret = telephonyManagerProxy->GetDefaultDataSim(data, simId);
    ASSERT_TRUE(ret == ERR_OK);
}

/**
 * @tc.name: TestGetDefaultDataSimFail
 * @tc.desc: Test GetDefaultDataSim without enable edm service func.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetDefaultDataSimFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    MessageParcel data;
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    data.WriteParcelable(&admin);
    int32_t simId = -1;
    int32_t ret = telephonyManagerProxy->GetDefaultDataSim(data, simId);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
}

/**
 * @tc.name: TestGetCallLogsSuc
 * @tc.desc: Test TelephonyManagerProxy::GetCallLogs when IPC returns valid call log data.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetCallLogsSuc, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetCallLogs));
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName("com.edm.test.demo.Ability");
    TelephonyQueryConfig config;
    config.startTime = 100;
    config.endTime = 200;
    config.hasTelephoneNumber = false;
    std::vector<CallLogInfo> callLogs;
    int32_t ret = telephonyManagerProxy->GetCallLogs(admin, config, callLogs);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(callLogs.size(), static_cast<size_t>(2));
    EXPECT_EQ(callLogs[0].createTime, static_cast<int64_t>(1700000000));
    EXPECT_EQ(callLogs[0].startTime, static_cast<int64_t>(1700000010));
    EXPECT_EQ(callLogs[0].endTime, static_cast<int64_t>(1700000020));
    EXPECT_TRUE(callLogs[0].isIncoming);
    EXPECT_EQ(callLogs[0].slotId, 0);
    EXPECT_EQ(callLogs[0].telephoneNumber, "13800138000");
    EXPECT_FALSE(callLogs[1].isIncoming);
    EXPECT_EQ(callLogs[1].slotId, 1);
    EXPECT_EQ(callLogs[1].telephoneNumber, "13800138001");
}

/**
 * @tc.name: TestGetCallLogsFail
 * @tc.desc: Test TelephonyManagerProxy::GetCallLogs when IPC SendRequest fails.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetCallLogsFail, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestReplyFail));
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName("com.edm.test.demo.Ability");
    TelephonyQueryConfig config;
    config.startTime = 100;
    config.endTime = 200;
    config.hasTelephoneNumber = false;
    std::vector<CallLogInfo> callLogs;
    int32_t ret = telephonyManagerProxy->GetCallLogs(admin, config, callLogs);
    EXPECT_NE(ret, ERR_OK);
    EXPECT_TRUE(callLogs.empty());
}

/**
 * @tc.name: TestGetCallLogsEmpty
 * @tc.desc: Test TelephonyManagerProxy::GetCallLogs when IPC returns empty result (dataSize=0).
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetCallLogsEmpty, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetCallLogsEmpty));
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName("com.edm.test.demo.Ability");
    TelephonyQueryConfig config;
    config.startTime = 100;
    config.endTime = 200;
    config.hasTelephoneNumber = false;
    std::vector<CallLogInfo> callLogs;
    int32_t ret = telephonyManagerProxy->GetCallLogs(admin, config, callLogs);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(callLogs.empty());
}

/**
 * @tc.name: TestGetCallLogsInvalidDataSize
 * @tc.desc: Test TelephonyManagerProxy::GetCallLogs when IPC returns negative dataSize.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetCallLogsInvalidDataSize, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSendRequestGetCallLogsInvalidSize));
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName("com.edm.test.demo.Ability");
    TelephonyQueryConfig config;
    config.startTime = 100;
    config.endTime = 200;
    config.hasTelephoneNumber = false;
    std::vector<CallLogInfo> callLogs;
    int32_t ret = telephonyManagerProxy->GetCallLogs(admin, config, callLogs);
    EXPECT_EQ(ret, EdmReturnErrCode::EXECUTE_TIME_OUT);
    EXPECT_TRUE(callLogs.empty());
}

/**
 * @tc.name: TestGetSmsMessagesSuc
 * @tc.desc: Test GetSmsMessages func success.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetSmsMessagesSuc, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSmsMessagesSendRequestGetPolicy));
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName("com.edm.test.demo.Ability");
    TelephonyQueryConfig config;
    config.startTime = 1000;
    config.endTime = 2000;
    config.hasTelephoneNumber = true;
    config.telephoneNumber = "13800000000";
    std::vector<SmsMessageInfo> messages;
    int32_t ret = telephonyManagerProxy->GetSmsMessages(admin, config, messages);
    ASSERT_TRUE(ret == ERR_OK);
    ASSERT_FALSE(messages.empty());
    ASSERT_TRUE(messages[0].slotId == 0);
    ASSERT_TRUE(messages[0].telephoneNumber == "13800000000");
    ASSERT_TRUE(messages[0].content == "hello");
    ASSERT_TRUE(messages[0].timer == 1722470500);
    ASSERT_TRUE(messages[0].isSender == true);
}

/**
 * @tc.name: TestGetSmsMessagesFail
 * @tc.desc: Test GetSmsMessages func without enabled edm service.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetSmsMessagesFail, TestSize.Level1)
{
    Utils::SetEdmServiceDisable();
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    TelephonyQueryConfig config;
    config.startTime = 1000;
    config.endTime = 2000;
    config.telephoneNumber = "13800000000";
    std::vector<SmsMessageInfo> messages;
    int32_t ret = telephonyManagerProxy->GetSmsMessages(admin, config, messages);
    ASSERT_TRUE(ret == EdmReturnErrCode::ADMIN_INACTIVE);
    ASSERT_TRUE(messages.empty());
}

/**
 * @tc.name: TestGetSmsMessagesIpcFail
 * @tc.desc: Test GetSmsMessages func with ipc failed.
 * @tc.type: FUNC
 */
HWTEST_F(TelephonyManagerProxyTest, TestGetSmsMessagesIpcFail, TestSize.Level1)
{
    EXPECT_CALL(*object_, SendRequest(_, _, _, _))
        .Times(1)
        .WillOnce(Invoke(object_.GetRefPtr(), &EnterpriseDeviceMgrStubMock::InvokeSmsMessagesSendRequestGetPolicyFail));
    OHOS::AppExecFwk::ElementName admin;
    admin.SetBundleName(ADMIN_PACKAGENAME);
    admin.SetAbilityName("com.edm.test.demo.Ability");
    TelephonyQueryConfig config;
    config.startTime = 1000;
    config.endTime = 2000;
    config.telephoneNumber = "13800000000";
    std::vector<SmsMessageInfo> messages;
    int32_t ret = telephonyManagerProxy->GetSmsMessages(admin, config, messages);
    ASSERT_TRUE(ret != ERR_OK);
    ASSERT_TRUE(messages.empty());
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
