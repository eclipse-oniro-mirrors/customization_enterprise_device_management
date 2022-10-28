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
class EnterpriseDeviceMgrStubMock : public IRemoteStub<IEnterpriseDeviceMgr> {
public:
    EnterpriseDeviceMgrStubMock() = default;

    virtual ~EnterpriseDeviceMgrStubMock() = default;

    MOCK_METHOD4(SendRequest, int(uint32_t, MessageParcel &, MessageParcel &, MessageOption &));

    int InvokeSendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    {
        GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequest code :" << code;
        code_ = code;
        reply.WriteInt32(ERR_OK);
        return 0;
    }

    int InvokeSendRequestGetEnterpriseInfo(uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option);

    int InvokeSendRequestEnableAdmin(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

    int InvokeSendRequestMapEnableAdminTwoSuc(uint32_t code, MessageParcel &data,
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

    ErrCode EnableAdmin(AppExecFwk::ElementName &admin, EntInfo &entInfo, AdminType type, int32_t userId) override
    {
        return 0;
    }

    ErrCode DisableAdmin(AppExecFwk::ElementName &admin, int32_t userId) override
    {
        return 0;
    }

    ErrCode DisableSuperAdmin(std::string &bundleName) override
    {
        return 0;
    }

    ErrCode HandleDevicePolicy(uint32_t code, AppExecFwk::ElementName &admin, MessageParcel &data) override
    {
        return 0;
    }

    ErrCode GetDevicePolicy(uint32_t code, AppExecFwk::ElementName *admin, MessageParcel &reply) override
    {
        return 0;
    }

    ErrCode GetEnabledAdmin(AdminType type, std::vector<std::string> &enabledAdminList) override
    {
        return 0;
    }

    ErrCode GetEnterpriseInfo(AppExecFwk::ElementName &admin, MessageParcel &reply) override
    {
        return 0;
    }

    ErrCode SetEnterpriseInfo(AppExecFwk::ElementName &admin, EntInfo &entInfo) override
    {
        return 0;
    }

    ErrCode SubscribeManagedEvent(const AppExecFwk::ElementName &admin, const std::vector<uint32_t> &events) override
    {
        return 0;
    }

    ErrCode UnsubscribeManagedEvent(const AppExecFwk::ElementName &admin, const std::vector<uint32_t> &events) override
    {
        return 0;
    }

    bool IsSuperAdmin(std::string &bundleName) override
    {
        return false;
    }

    bool IsAdminEnabled(AppExecFwk::ElementName &admin, int32_t userId) override
    {
        return false;
    }

    uint32_t code_ = 0;
};
} // namespace EDM
} // namespace OHOS
#endif // EDM_UNIT_TEST_ENTERPRISE_DEVICE_MGR_STUB_MOCK_H