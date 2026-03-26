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

#include "net_stats_utils.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace EDM {
namespace TEST {
class NetStatsUtilsTest : public testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};

/**
 * @tc.name: TestNetStatsNetworkMarshalling
 * @tc.desc: Test NetStatsNetwork marshalling and unmarshalling.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsUtilsTest, TestNetStatsNetworkMarshalling, TestSize.Level1)
{
    NetStatsNetwork networkInfo;
    networkInfo.bundleName = "com.test.app";
    networkInfo.appIndex = 0;
    networkInfo.accountId = 100;
    networkInfo.type = 1;
    networkInfo.startTime = 1000;
    networkInfo.endTime = 2000;
    networkInfo.simId = 12345;

    MessageParcel parcel;
    ASSERT_TRUE(networkInfo.Marshalling(parcel));

    NetStatsNetwork unmarshalledInfo;
    ASSERT_TRUE(NetStatsNetwork::Unmarshalling(parcel, unmarshalledInfo));

    ASSERT_EQ(networkInfo.bundleName, unmarshalledInfo.bundleName);
    ASSERT_EQ(networkInfo.appIndex, unmarshalledInfo.appIndex);
    ASSERT_EQ(networkInfo.accountId, unmarshalledInfo.accountId);
    ASSERT_EQ(networkInfo.type, unmarshalledInfo.type);
    ASSERT_EQ(networkInfo.startTime, unmarshalledInfo.startTime);
    ASSERT_EQ(networkInfo.endTime, unmarshalledInfo.endTime);
    ASSERT_EQ(networkInfo.simId, unmarshalledInfo.simId);
}

/**
 * @tc.name: TestNetStatsInfoMarshalling
 * @tc.desc: Test NetStatsInfo marshalling and unmarshalling.
 * @tc.type: FUNC
 */
HWTEST_F(NetStatsUtilsTest, TestNetStatsInfoMarshalling, TestSize.Level1)
{
    NetStatsInfo netStatsInfo;
    netStatsInfo.rxBytes = 1024;
    netStatsInfo.txBytes = 2048;
    netStatsInfo.rxPackets = 100;
    netStatsInfo.txPackets = 200;

    MessageParcel parcel;
    ASSERT_TRUE(netStatsInfo.Marshalling(parcel));

    NetStatsInfo unmarshalledInfo;
    ASSERT_TRUE(NetStatsInfo::Unmarshalling(parcel, unmarshalledInfo));

    ASSERT_EQ(netStatsInfo.rxBytes, unmarshalledInfo.rxBytes);
    ASSERT_EQ(netStatsInfo.txBytes, unmarshalledInfo.txBytes);
    ASSERT_EQ(netStatsInfo.rxPackets, unmarshalledInfo.rxPackets);
    ASSERT_EQ(netStatsInfo.txPackets, unmarshalledInfo.txPackets);
}
} // namespace TEST
} // namespace EDM
} // namespace OHOS
