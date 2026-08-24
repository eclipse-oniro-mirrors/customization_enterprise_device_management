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
 
#include "plugin_utils/ip_utils.h"
 
using namespace testing::ext;
using namespace testing;
 
namespace OHOS {
namespace EDM {
namespace Utils {
namespace TEST {
 
class IpUtilsTest : public testing::Test {
protected:
    static void SetUpTestSuite(void);
    static void TearDownTestSuite(void);
};
 
void IpUtilsTest::SetUpTestSuite(void)
{
}
 
void IpUtilsTest::TearDownTestSuite(void)
{
}
 
/**
 * @tc.name: TestIsValidIPv4Valid
 * @tc.desc: Test valid IPv4 addresses.
 * @tc.type: FUNC
 */
HWTEST_F(IpUtilsTest, TestIsValidIPv4Valid, TestSize.Level1)
{
    ASSERT_TRUE(IpUtils::IsValidIPv4("192.168.1.1"));
    ASSERT_TRUE(IpUtils::IsValidIPv4("10.0.0.1"));
    ASSERT_TRUE(IpUtils::IsValidIPv4("172.16.0.1"));
    ASSERT_TRUE(IpUtils::IsValidIPv4("0.0.0.0"));
    ASSERT_TRUE(IpUtils::IsValidIPv4("255.255.255.255"));
    ASSERT_TRUE(IpUtils::IsValidIPv4("127.0.0.1"));
}
 
/**
 * @tc.name: TestIsValidIPv4Invalid
 * @tc.desc: Test invalid IPv4 addresses.
 * @tc.type: FUNC
 */
HWTEST_F(IpUtilsTest, TestIsValidIPv4Invalid, TestSize.Level1)
{
    ASSERT_FALSE(IpUtils::IsValidIPv4("256.1.1.1"));
    ASSERT_FALSE(IpUtils::IsValidIPv4("192.168.1"));
    ASSERT_FALSE(IpUtils::IsValidIPv4("192.168.1.1.1"));
    ASSERT_FALSE(IpUtils::IsValidIPv4("192.168.1.a"));
    ASSERT_FALSE(IpUtils::IsValidIPv4("abc.def.ghi.jkl"));
    ASSERT_FALSE(IpUtils::IsValidIPv4(""));
    ASSERT_FALSE(IpUtils::IsValidIPv4("192.168.1.1 "));
    ASSERT_FALSE(IpUtils::IsValidIPv4(" 192.168.1.1"));
    ASSERT_FALSE(IpUtils::IsValidIPv4("-1.0.0.1"));
    ASSERT_FALSE(IpUtils::IsValidIPv4("192.168.1."));
}
 
/**
 * @tc.name: TestIsValidIPv4Boundary
 * @tc.desc: Test IPv4 address boundary values.
 * @tc.type: FUNC
 */
HWTEST_F(IpUtilsTest, TestIsValidIPv4Boundary, TestSize.Level1)
{
    ASSERT_TRUE(IpUtils::IsValidIPv4("0.0.0.0"));
    ASSERT_TRUE(IpUtils::IsValidIPv4("255.255.255.255"));
    ASSERT_TRUE(IpUtils::IsValidIPv4("0.0.0.1"));
    ASSERT_TRUE(IpUtils::IsValidIPv4("254.255.255.255"));
}
 
/**
 * @tc.name: TestIsValidIPv6Valid
 * @tc.desc: Test valid IPv6 addresses (strict full format only, no abbreviations).
 * @tc.type: FUNC
 */
HWTEST_F(IpUtilsTest, TestIsValidIPv6Valid, TestSize.Level1)
{
    ASSERT_TRUE(IpUtils::IsValidIPv6("2001:0db8:0000:0000:0000:0000:0000:0001"));
    ASSERT_TRUE(IpUtils::IsValidIPv6("fe80:0000:0000:0000:0000:0000:0000:0001"));
    ASSERT_TRUE(IpUtils::IsValidIPv6("0000:0000:0000:0000:0000:0000:0000:0001"));
    ASSERT_TRUE(IpUtils::IsValidIPv6("0000:0000:0000:0000:0000:0000:0000:0000"));
    ASSERT_TRUE(IpUtils::IsValidIPv6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    ASSERT_TRUE(IpUtils::IsValidIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
}
 
/**
 * @tc.name: TestIsValidIPv6Invalid
 * @tc.desc: Test invalid IPv6 addresses (abbreviations and other invalid formats).
 * @tc.type: FUNC
 */
HWTEST_F(IpUtilsTest, TestIsValidIPv6Invalid, TestSize.Level1)
{
    ASSERT_FALSE(IpUtils::IsValidIPv6(""));
    ASSERT_FALSE(IpUtils::IsValidIPv6("192.168.1.1"));
    ASSERT_FALSE(IpUtils::IsValidIPv6("gggg::1"));
    ASSERT_FALSE(IpUtils::IsValidIPv6("::1"));
    ASSERT_FALSE(IpUtils::IsValidIPv6("fe80::1"));
    ASSERT_FALSE(IpUtils::IsValidIPv6("2001:db8::1"));
    ASSERT_FALSE(IpUtils::IsValidIPv6("::"));
    ASSERT_FALSE(IpUtils::IsValidIPv6("::0"));
    ASSERT_FALSE(IpUtils::IsValidIPv6("1::"));
    ASSERT_FALSE(IpUtils::IsValidIPv6("2001:db8::8:800:200c:417a"));
}
 
/**
 * @tc.name: TestIsValidIpAddressIPv4
 * @tc.desc: Test valid IP address (IPv4).
 * @tc.type: FUNC
 */
HWTEST_F(IpUtilsTest, TestIsValidIpAddressIPv4, TestSize.Level1)
{
    ASSERT_TRUE(IpUtils::IsValidIpAddress("192.168.1.1"));
    ASSERT_TRUE(IpUtils::IsValidIpAddress("10.0.0.1"));
    ASSERT_TRUE(IpUtils::IsValidIpAddress("255.255.255.255"));
}
 
/**
 * @tc.name: TestIsValidIpAddressIPv6
 * @tc.desc: Test valid IP address (IPv6 full format).
 * @tc.type: FUNC
 */
HWTEST_F(IpUtilsTest, TestIsValidIpAddressIPv6, TestSize.Level1)
{
    ASSERT_TRUE(IpUtils::IsValidIpAddress("2001:0db8:0000:0000:0000:0000:0000:0001"));
    ASSERT_TRUE(IpUtils::IsValidIpAddress("fe80:0000:0000:0000:0000:0000:0000:0001"));
    ASSERT_TRUE(IpUtils::IsValidIpAddress("0000:0000:0000:0000:0000:0000:0000:0001"));
}
 
/**
 * @tc.name: TestIsValidIpAddressInvalid
 * @tc.desc: Test invalid IP address.
 * @tc.type: FUNC
 */
HWTEST_F(IpUtilsTest, TestIsValidIpAddressInvalid, TestSize.Level1)
{
    ASSERT_FALSE(IpUtils::IsValidIpAddress(""));
    ASSERT_FALSE(IpUtils::IsValidIpAddress("invalid"));
    ASSERT_FALSE(IpUtils::IsValidIpAddress("256.1.1.1"));
    ASSERT_FALSE(IpUtils::IsValidIpAddress("192.168.1"));
}
} // namespace TEST
} // namespace Utils
} // namespace EDM
} // namespace OHOS