/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "uninstall_param_serializer.h"

namespace OHOS {
namespace EDM {
bool UninstallParamSerializer::Deserialize(const std::string &jsonString, UninstallParam &config)
{
    return true;
}

bool UninstallParamSerializer::Serialize(const UninstallParam &config, std::string &jsonString)
{
    return true;
}

bool UninstallParamSerializer::GetPolicy(MessageParcel &data, UninstallParam &result)
{
    result.bundleName = data.ReadString();
    result.userId = data.ReadInt32();
    result.isKeepData = data.ReadBool();
    return true;
}

bool UninstallParamSerializer::WritePolicy(MessageParcel &reply, UninstallParam &result)
{
    return true;
}

bool UninstallParamSerializer::MergePolicy(std::vector<UninstallParam> &data, UninstallParam &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS