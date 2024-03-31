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

#include "enterprise_device_mgr_stub_mock.h"

#include "domain_filter_rule.h"
#include "firewall_rule.h"
#include "http_proxy.h"
#include "iptables_utils.h"
#include "os_account_info.h"
#include "usb_device_id.h"

namespace OHOS {
namespace EDM {
int EnterpriseDeviceMgrStubMock::InvokeSendRequestGetEnterpriseInfo(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestGetEnterpriseInfo code :" << code;
    EntInfo entInfo;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    entInfo.Marshalling(reply);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeSendRequestEnableAdmin(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestEnableAdmin code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    std::vector<std::string> writeArray{"com.edm.test.demo"};
    reply.WriteInt32(writeArray.size());
    reply.WriteStringVector(writeArray);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeSendRequestMapEnableAdminTwoSuc(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestMapEnableAdminTwoSuc code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    std::vector<std::string> writeArray{"com.edm.test.demo"};
    reply.WriteStringVector(writeArray);

    std::vector<std::string> writeArray2{"set date time policy"};
    reply.WriteStringVector(writeArray2);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeSendRequestSetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestGetPolicy code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeSendRequestGetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestGetPolicy code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    reply.WriteString(RETURN_STRING);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetPolicy(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestGetPolicy code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(true);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeBoolSendRequestGetFirewallRule(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeBoolSendRequestGetFirewallRule code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(1);
    IPTABLES::DomainFilterRule rule{IPTABLES::Action::INVALID, "321", "www.example.com"};
    IPTABLES::DomainFilterRuleParcel ruleParcel{rule};
    ruleParcel.Marshalling(reply);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeSendRequestGetDomainFilterRules(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestGetDomainFilterRules code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(1);
    IPTABLES::FirewallRule rule{IPTABLES::Direction::INVALID, IPTABLES::Action::INVALID, IPTABLES::Protocol::INVALID,
        "", "", "", "", ""};
    IPTABLES::FirewallRuleParcel ruleParcel{rule};
    ruleParcel.Marshalling(reply);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeIntSendRequestGetPolicy(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeIntSendRequestGetPolicy code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(0);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeArrayStringSendRequestGetPolicy(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestGetPolicy code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(1);
    reply.WriteStringVector(std::vector<std::string>{RETURN_STRING});
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeArrayElementSendRequestGetPolicy(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestGetPolicy code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    reply.WriteStringVector(std::vector<std::string>{ELEMENT_STRING});
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeSendRequestParamError(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestGetPolicy code :" << code;
    code_ = code;
    reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
    reply.WriteString(RETURN_STRING);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeHttpProxySendRequestGetPolicy(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeHttpProxySendRequestGetPolicy code :" << code;
    code_ = code;
    OHOS::NetManagerStandard::HttpProxy httpProxy;
    reply.WriteInt32(ERR_OK);
    httpProxy.Marshalling(reply);
    return ERR_OK;
}

int EnterpriseDeviceMgrStubMock::InvokeBluetoothProxySendRequestGetPolicy(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeBluetoothProxySendRequestGetPolicy code :" << code;
    EntInfo entInfo;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    reply.WriteString(RETURN_STRING);
    reply.WriteInt32(1);
    reply.WriteInt32(1);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeAccountProxySendRequestAddOsAccount(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeOsAccountProxySendRequestGetPolicy code :" << code;
    OHOS::AccountSA::OsAccountInfo accountInfo;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    accountInfo.SetLocalName(RETURN_STRING);
    accountInfo.Marshalling(reply);
    reply.WriteString(RETURN_STRING);
    reply.WriteString(RETURN_STRING);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeAllowedUsbDevicesSendRequestGetPolicy(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeAllowedUsbDevicesSendRequestGetPolicy code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    std::vector<UsbDeviceId> usbDeviceIds;
    UsbDeviceId id1;
    int32_t testVid = 1;
    int32_t testPid = 9;
    id1.SetVendorId(testVid);
    id1.SetProductId(testPid);
    usbDeviceIds.push_back(id1);
    reply.WriteInt32(usbDeviceIds.size());
    std::for_each(usbDeviceIds.begin(), usbDeviceIds.end(), [&](const auto usbDeviceId) {
        usbDeviceId.Marshalling(reply);
    });
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeSendRequestGetSuperAdmin(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestGetSuperAdmin code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    reply.WriteString(RETURN_STRING);
    reply.WriteString(RETURN_STRING);
    return 0;
}
} // namespace EDM
} // namespace OHOS
