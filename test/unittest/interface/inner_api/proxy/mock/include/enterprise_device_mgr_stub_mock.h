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

#ifndef EDM_UNIT_TEST_ENTERPRISE_DEVICE_MGR_STUB_MOCK_H
#define EDM_UNIT_TEST_ENTERPRISE_DEVICE_MGR_STUB_MOCK_H

#include <gmock/gmock.h>
#include <iremote_stub.h>

#include <map>
#include <vector>

#include "ienterprise_device_mgr.h"
#include "string_ex.h"

namespace OHOS {
namespace EDM {
constexpr int ERR_PROXY_SENDREQUEST_FAIL = 111;
constexpr int EDM_MAXREQUESTSIZE = 99999;
const std::string RETURN_STRING = "test_string";
const std::string ELEMENT_STRING = "com.example.myapplication/MainAbility";
const std::string UPGRADE_VERSION = "version_1.0";
constexpr int32_t UPGRADE_FAILED_CODE = -1;
const std::string UPGRADE_FAILED_MESSAGE = "upgrade failed";
const std::string AUTH_DATA = "auth data";
class EnterpriseDeviceMgrStubMock : public IRemoteStub<IEnterpriseDeviceMgrIdl> {
public:
    EnterpriseDeviceMgrStubMock() = default;

    virtual ~EnterpriseDeviceMgrStubMock() = default;

    MOCK_METHOD4(SendRequest, int(uint32_t, MessageParcel &, MessageParcel &, MessageOption &));
    MOCK_METHOD(int, EnableAdmin, (const AppExecFwk::ElementName &, const EntInfo &, AdminType, int32_t), (override));
    MOCK_METHOD(int, DisableAdmin, (const AppExecFwk::ElementName &, int32_t), (override));
    MOCK_METHOD(int, DisableSuperAdmin, (const std::string &), (override));
    MOCK_METHOD(int, GetEnabledAdmin, (AdminType, (std::vector<std::string> &)), (override));
    MOCK_METHOD(int, GetEnterpriseInfo, (const AppExecFwk::ElementName &, EntInfo &), (override));
    MOCK_METHOD(int, SetEnterpriseInfo, (const AppExecFwk::ElementName &, const EntInfo &), (override));
    MOCK_METHOD(int, IsSuperAdmin, (const std::string &, bool &), (override));
    MOCK_METHOD(int, IsByodAdmin, (const AppExecFwk::ElementName &, bool &), (override));
    MOCK_METHOD(int, IsAdminEnabled, (const AppExecFwk::ElementName &, int32_t, bool &), (override));
    MOCK_METHOD(int, SubscribeManagedEvent, (const AppExecFwk::ElementName &, (const std::vector<uint32_t> &)),
        (override));
    MOCK_METHOD(int, UnsubscribeManagedEvent, (const AppExecFwk::ElementName &, (const std::vector<uint32_t> &)),
        (override));
    MOCK_METHOD(int, AuthorizeAdmin, (const AppExecFwk::ElementName &, const std::string &), (override));
    MOCK_METHOD(int, GetSuperAdmin, (std::string &, std::string &), (override));
    MOCK_METHOD(int, SetDelegatedPolicies,
        (const AppExecFwk::ElementName &, const std::string &, (const std::vector<std::string> &)), (override));
    MOCK_METHOD(int, GetDelegatedPolicies,
        (const AppExecFwk::ElementName &, const std::string &, (std::vector<std::string> &)), (override));
    MOCK_METHOD(int, GetDelegatedBundleNames,
        (const AppExecFwk::ElementName &, const std::string &, (std::vector<std::string> &)), (override));
    MOCK_METHOD(int, ReplaceSuperAdmin, (const AppExecFwk::ElementName &, const AppExecFwk::ElementName &, bool),
        (override));
    MOCK_METHOD(int, GetAdmins, ((std::vector<std::shared_ptr<AAFwk::Want>> &)), (override));
    MOCK_METHOD(int, SetAdminRunningMode, (const AppExecFwk::ElementName &, uint32_t), (override));
    MOCK_METHOD(int, SetDelegatedPolicies, (const std::string &, (const std::vector<std::string> &), int32_t),
        (override));
    MOCK_METHOD(int, SetBundleInstallPolicies, ((const std::vector<std::string> &), int32_t, int32_t),
    MOCK_METHOD(int, UnloadInstallMarketAppsPlugin, (), (override));
    MOCK_METHOD(int, ReportAgInstallStatus, (const std::string &, int32_t),
        (override));

    int InvokeSendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    {
        GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequest code :" << code;
        code_ = code;
        reply.WriteInt32(ERR_OK);
        return 0;
    }

    int InvokeGetEnterpriseInfo(const AppExecFwk::ElementName &admin, EntInfo &entInfo);
    int InvokeGetEnterpriseInfoFail(const AppExecFwk::ElementName &admin, EntInfo &entInfo);
    int InvokeIsAdminEnabledFail(const AppExecFwk::ElementName &admin, int32_t userId, bool &isEnabled);
    int InvokeIsSuperAdminFail(const std::string &bundleName, bool &isSuper);
    int InvokeIsByodAdminFail(const AppExecFwk::ElementName &admin, bool &isByod);
    int InvokeGetSuperAdmin(std::string &bundleName, std::string &abilityName);
    int InvokeGetAdmins(std::vector<std::shared_ptr<AAFwk::Want>> &wants);
    int InvokeGetEnabledAdmin(AdminType type, std::vector<std::string> &enabledAdminList);

    int InvokeSendRequestEnableAdmin(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    int InvokeSendRequestMapEnableAdminTwoSuc(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeSendRequestSetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    int InvokeSendRequestGetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    int InvokeBoolSendRequestGetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    int InvokeBoolSendRequestGetFirewallRule(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeSendRequestGetDomainFilterRules(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeIntSendRequestGetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    int InvokeSendRequestGetPolicyForWriteFileToStream(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeSendRequestSetPolicyInstallFail(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeArrayStringSendRequestGetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeSendRequestGetErrPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    int InvokeSendRequestGetPolicyExceedsMax(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeArrayElementSendRequestGetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeHttpProxySendRequestGetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeSendRequestParamError(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    int InvokeBluetoothProxySendRequestGetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeAccountProxySendRequestAddOsAccount(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeAllowedUsbDevicesSendRequestGetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeWifiListSendRequestGetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeArrayIntSendRequestGetPolicy(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option);

    int InvokeDisallowedUsbDevicesSendRequestGetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeSendRequestGetSuperAdmin(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    int InvokeSendRequestGetOTAUpdatePolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeSendRequestGetUpgradeResult(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeSendRequestGetUpdateAuthData(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);

    int InvokeSendRequestGetPasswordPolicy(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option);

    int InvokeSendRequestGetManagedBrowserPolicy(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option);

    int InvokeSendRequestGetAdmins(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option);

    int InvokeSendRequestCheckAndGetAdminProvisionInfo(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option);

    int InvokeSendRequestGetInstalledBundleList(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option);

    int InvokeSendRequestReplyFail(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    {
        GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestReplyFail code :" << code;
        code_ = code;
        reply.WriteInt32(ERR_PROXY_SENDREQUEST_FAIL);
        return 0;
    }

    int InvokeSendRequestFail(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    {
        GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestFail code :" << code;
        code_ = code;
        return ERR_PROXY_SENDREQUEST_FAIL;
    }

    int InvokeSendRequestSizeError(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option);
    uint32_t code_ = 0;
};
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_ENTERPRISE_DEVICE_MGR_STUB_MOCK_H