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

#include "apn_info_utils.h"

namespace OHOS {
namespace EDM {
    ApnInfoParcel::ApnInfoParcel(ApnInfo info) : info_(std::move(info)) {}

bool ApnInfoParcel::Marshalling(MessageParcel& parcel) const
{
    parcel.WriteString(std::get<APNINFO_APNNAME_IND>(info_));
    parcel.WriteString(std::get<APNINFO_APN_IND>(info_));
    parcel.WriteString(std::get<APNINFO_MCC_IND>(info_));
    parcel.WriteString(std::get<APNINFO_MNC_IND>(info_));
    parcel.WriteString(std::get<APNINFO_USER_IND>(info_));
    parcel.WriteString(std::get<APNINFO_TYPE_IND>(info_));
    parcel.WriteString(std::get<APNINFO_PROXY_IND>(info_));
    parcel.WriteString(std::get<APNINFO_MMSPROXY_IND>(info_));
    return true;
}

bool ApnInfoParcel::Unmarshalling(MessageParcel& parcel, ApnInfoParcel& apnInfoParcel)
{
    std::string apnName = parcel.ReadString();
    std::string apn = parcel.ReadString();
    std::string mcc = parcel.ReadString();
    std::string mnc = parcel.ReadString();
    std::string user = parcel.ReadString();
    std::string type = parcel.ReadString();
    std::string proxy = parcel.ReadString();
    std::string mmsproxy = parcel.ReadString();
    apnInfoParcel.info_ = {apnName, apn, mcc, mnc, user, type, proxy, mmsproxy};
    return true;
}

ApnInfo ApnInfoParcel::GetInfo() const
{
    return info_;
}
} // namespace EDM
} // namespace OHOS