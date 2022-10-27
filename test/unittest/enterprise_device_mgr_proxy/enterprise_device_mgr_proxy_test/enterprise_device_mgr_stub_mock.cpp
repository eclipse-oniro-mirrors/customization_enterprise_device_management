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

#include "enterprise_device_mgr_stub_mock.h"

namespace OHOS {
namespace EDM {
int EnterpriseDeviceMgrStubMock::InvokeSendRequestGetEnterpriseInfo(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestGetEnterpriseInfo code :" << code;
    EntInfo entInfo;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    reply.WriteParcelable(&entInfo);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeSendRequestEnableAdmin(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestEnableAdmin code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    std::vector<std::u16string> writeArray{Str8ToStr16("com.edm.test.demo")};
    reply.WriteString16Vector(writeArray);
    return 0;
}

int EnterpriseDeviceMgrStubMock::InvokeSendRequestMapEnableAdminTwoSuc(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    GTEST_LOG_(INFO) << "mock EnterpriseDeviceMgrStubMock InvokeSendRequestMapEnableAdminTwoSuc code :" << code;
    code_ = code;
    reply.WriteInt32(ERR_OK);
    std::vector<std::u16string> writeArray{Str8ToStr16("com.edm.test.demo")};
    reply.WriteString16Vector(writeArray);

    std::vector<std::u16string> writeArray2{Str8ToStr16("set date time policy")};
    reply.WriteString16Vector(writeArray2);
    return 0;
}
} // namespace EDM
} // namespace OHOS
