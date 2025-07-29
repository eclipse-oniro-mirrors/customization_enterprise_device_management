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
#ifndef EDM_ANI_UTILS_H
#define EDM_ANI_UTILS_H

#include <string>
#include <unordered_map>
#include "ani.h"
#include "element_name.h"

namespace OHOS {
namespace EDM {
class EdmAniUtils {
public:
    static void AniThrow(ani_env *env, int32_t errCode);
    static void AniThrow(ani_env *env, int32_t errCode, std::string errMsg);
    static std::string AniStrToString(ani_env *env, ani_ref aniStr);
    static ani_string StringToAniStr(ani_env *env, const std::string &str);
    static bool UnWrapAdmin(ani_env *env, ani_object aniAdmin, AppExecFwk::ElementName &admin);
    static bool GetStringProperty(ani_env *env,  ani_object aniAdmin, const std::string &propertyName,
        std::string &property);
    static bool SetNumberMember(ani_env *env, ani_object obj, const std::string &name, const ani_long value);

private:
    static const std::unordered_map<int32_t, std::string> errMessageMap;
    static std::string FindErrMsg(int32_t errCode);
};
} // namespace EDM
} // namespace OHOS
#endif