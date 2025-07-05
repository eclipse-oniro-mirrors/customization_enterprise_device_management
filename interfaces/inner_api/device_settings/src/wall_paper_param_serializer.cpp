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

#include "wall_paper_param_serializer.h"
#include "message_parcel_utils.h"

namespace OHOS {
namespace EDM {
bool WallPaperParamSerializer::Deserialize(const std::string &jsonString, WallPaperParam &config)
{
    return true;
}

bool WallPaperParamSerializer::Serialize(const WallPaperParam &config, std::string &jsonString)
{
    return true;
}

bool WallPaperParamSerializer::GetPolicy(MessageParcel &data, WallPaperParam &result)
{
    result.fd = data.ReadFileDescriptor();
    result.isHomeWallPaper = data.ReadBool();
    return true;
}

bool WallPaperParamSerializer::WritePolicy(MessageParcel &reply, WallPaperParam &result)
{
    return true;
}

bool WallPaperParamSerializer::MergePolicy(std::vector<WallPaperParam> &data, WallPaperParam &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS