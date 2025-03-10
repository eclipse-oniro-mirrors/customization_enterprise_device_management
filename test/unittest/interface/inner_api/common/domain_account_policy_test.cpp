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

#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "domain_account_policy.h"
#include "message_parcel.h"

using namespace testing::ext;

namespace OHOS {
namespace EDM {
namespace TEST {
const int32_t AUTHENTICATIONVALIDITYPERIOD{300};
const int32_t PASSWORDVALIDITYPERIOD{200};
const int32_t PASSWORDEXPIRATIONNOTIFICATION{100};

class DomainAccountPolicyTest : public testing::Test {
protected:
    void SetUp() override;

    void TearDown() override;

    std::shared_ptr<DomainAccountPolicy> domainAccountPolicyTest;
};

void DomainAccountPolicyTest::SetUp()
{
    domainAccountPolicyTest = std::make_shared<DomainAccountPolicy>(AUTHENTICATIONVALIDITYPERIOD,
        PASSWORDVALIDITYPERIOD, PASSWORDEXPIRATIONNOTIFICATION);
}

void DomainAccountPolicyTest::TearDown()
{
    if (domainAccountPolicyTest) {
        domainAccountPolicyTest.reset();
    }
}

/**
 * @tc.name: TestMarshalling
 * @tc.desc: Test Marshalling func.
 * @tc.type: FUNC
 */
HWTEST_F(DomainAccountPolicyTest, TestMarshalling, TestSize.Level1)
{
    MessageParcel parcel;
    bool ret = domainAccountPolicyTest->Marshalling(parcel);
    ASSERT_TRUE(ret);

    DomainAccountPolicy domainAccountPolicy;
    ASSERT_TRUE(DomainAccountPolicy::Unmarshalling(parcel, domainAccountPolicy));

    ASSERT_TRUE(domainAccountPolicy.authenticationValidityPeriod == AUTHENTICATIONVALIDITYPERIOD);
    ASSERT_TRUE(domainAccountPolicy.passwordValidityPeriod == PASSWORDVALIDITYPERIOD);
    ASSERT_TRUE(domainAccountPolicy.passwordExpirationNotification == PASSWORDEXPIRATIONNOTIFICATION);
    ASSERT_TRUE(domainAccountPolicy.authenticationValidityPeriod ==
        domainAccountPolicyTest->authenticationValidityPeriod);
    ASSERT_TRUE(domainAccountPolicy.passwordValidityPeriod == domainAccountPolicyTest->passwordValidityPeriod);
    ASSERT_TRUE(domainAccountPolicy.passwordExpirationNotification ==
        domainAccountPolicyTest->passwordExpirationNotification);

    MessageParcel parcelErrData;
    DomainAccountPolicy domainAccountPolicy2;
    ASSERT_FALSE(DomainAccountPolicy::Unmarshalling(parcelErrData, domainAccountPolicy2));
}

/**
 * @tc.name: TestConvertDomainAccountPolicyToJsonStr
 * @tc.desc: Test ConvertDomainAccountPolicyToJsonStr func.
 * @tc.type: FUNC
 */
HWTEST_F(DomainAccountPolicyTest, TestConvertDomainAccountPolicyToJsonStr, TestSize.Level1)
{
    std::string jsonStr;
    bool ret = domainAccountPolicyTest->ConvertDomainAccountPolicyToJsonStr(jsonStr);
    ASSERT_TRUE(ret);

    DomainAccountPolicy domainAccountPolicy;
    ASSERT_TRUE(DomainAccountPolicy::JsonStrToDomainAccountPolicy(jsonStr, domainAccountPolicy));

    ASSERT_TRUE(domainAccountPolicy.authenticationValidityPeriod ==
        domainAccountPolicyTest->authenticationValidityPeriod);
    ASSERT_TRUE(domainAccountPolicy.passwordValidityPeriod == domainAccountPolicyTest->passwordValidityPeriod);
    ASSERT_TRUE(domainAccountPolicy.passwordExpirationNotification ==
        domainAccountPolicyTest->passwordExpirationNotification);

    std::string jsonStr2 = "{\"authenticationValidityPeriod\":-1}";
    DomainAccountPolicy domainAccountPolicy2;
    ASSERT_TRUE(DomainAccountPolicy::JsonStrToDomainAccountPolicy(jsonStr2, domainAccountPolicy2));

    std::string jsonStr3 = "{\"authenticationValidityPeriod\":\"errData\",\"passwordMaximumAge\":\"errData\","        \
        "\"passwordExpirationNotification\":\"errData\"}";
    DomainAccountPolicy domainAccountPolicy3;
    ASSERT_FALSE(DomainAccountPolicy::JsonStrToDomainAccountPolicy(jsonStr3, domainAccountPolicy3));
}

/**
 * @tc.name: TestCheckParameterValidity
 * @tc.desc: Test CheckParameterValidity func.
 * @tc.type: FUNC
 */
HWTEST_F(DomainAccountPolicyTest, TestCheckParameterValidity, TestSize.Level1)
{
    bool ret = domainAccountPolicyTest->CheckParameterValidity();
    ASSERT_TRUE(ret);

    DomainAccountPolicy domainAccountPolicyInValid1(-2, -2, -2);
    ASSERT_FALSE(domainAccountPolicyInValid1.CheckParameterValidity());
    DomainAccountPolicy domainAccountPolicyInValid2(2, -2, -2);
    ASSERT_FALSE(domainAccountPolicyInValid2.CheckParameterValidity());
    DomainAccountPolicy domainAccountPolicyInValid3(-2, 2, -2);
    ASSERT_FALSE(domainAccountPolicyInValid3.CheckParameterValidity());
    DomainAccountPolicy domainAccountPolicyInValid4(-2, -2, 2);
    ASSERT_FALSE(domainAccountPolicyInValid4.CheckParameterValidity());
}

/**
 * @tc.name: TestIsParameterNeedShow
 * @tc.desc: Test IsParameterNeedShow func.
 * @tc.type: FUNC
 */
HWTEST_F(DomainAccountPolicyTest, TestIsParameterNeedShow, TestSize.Level1)
{
    DomainAccountPolicy domainAccountPolicy;
    ASSERT_FALSE(domainAccountPolicy.IsParameterNeedShow(INT32_MIN));
    ASSERT_TRUE(domainAccountPolicy.IsParameterNeedShow(0));
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
