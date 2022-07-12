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

#ifndef COMMON_NATIVE_INCLUDE_EDM_FUNC_CODE_H
#define COMMON_NATIVE_INCLUDE_EDM_FUNC_CODE_H

#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace EDM {
/*
 * FuncCode layout
 *
 * +-----+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * | Bit |31|30|29|28|27|26|25|24|23|22|21|20|19|18|17|16|15|14|13|12|11|10|09|08|07|06|05|04|03|02|01|00|
 * +-----+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Field|       Reserved        |SystemFlag |                                 Code                      |
 * +-----+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 * |Field|       Reserved        |PolicyFlag |OperateType|  PolicyCode                                   |
 * +-----+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */

enum class FuncFlag {
    SERVICE_FLAG = 0,
    POLICY_FLAG = 1,
    UNKNOWN = 0xF,
};

enum class FuncOperateType {
    GET = 0,
    SET = 1,
    REMOVE = 2,
    UNKNOWN = 0xF,
};

#define FUNC_TO_FLAG(CODE) (((CODE) & 0x00F00000) >> 20)
#define FUNC_TO_OPERATE(CODE) (((CODE) & 0x000F0000) >> 16)
#define FUNC_TO_POLICY(CODE) (((CODE) & 0x0000FFFF))
#define SERVICE_FLAG(CODE) ((((CODE) & 0x00F00000) >> 20) == 0)
#define POLICY_FLAG(CODE) ((((CODE) & 0x00F00000) >> 20) == 1)
#define CREATE_FUNC_CODE(FLAG, OPERATE_TYPE, POLICY) (((FLAG) << 20) | ((OPERATE_TYPE) << 16) | (POLICY))
#define POLICY_FUNC_CODE(OPERATE_TYPE, POLICY) CREATE_FUNC_CODE(1, OPERATE_TYPE, POLICY)
} // namespace EDM
} // namespace OHOS
#endif // COMMON_NATIVE_INCLUDE_EDM_FUNC_CODE_H
