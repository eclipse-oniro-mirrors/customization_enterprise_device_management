/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "http_proxy.h"

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
} // namespace EDM
} // namespace OHOS
