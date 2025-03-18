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

#include "install_param_serializer.h"

namespace OHOS {
namespace EDM {
bool InstallParamSerializer::Deserialize(const std::string &jsonString, InstallParam &config)
{
    return true;
}

bool InstallParamSerializer::Serialize(const InstallParam &config, std::string &jsonString)
{
    return true;
}

bool InstallParamSerializer::GetPolicy(MessageParcel &data, InstallParam &result)
{
    data.ReadStringVector(&result.hapFilePaths);
    result.userId = data.ReadInt32();
    result.installFlag = data.ReadInt32();
    std::vector<std::string> keys;
    std::vector<std::string> values;
    data.ReadStringVector(&keys);
    data.ReadStringVector(&values);
    if (keys.size() != values.size()) {
        EDMLOGE("key and value size is not equal");
        return false;
    }
    for (size_t i = 0; i < keys.size(); ++i) {
        result.parameters[keys[i]] = values[i];
    }
    return true;
}

bool InstallParamSerializer::WritePolicy(MessageParcel &reply, InstallParam &result)
{
    return true;
}

bool InstallParamSerializer::MergePolicy(std::vector<InstallParam> &data, InstallParam &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS