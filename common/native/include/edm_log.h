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

#ifndef COMMON_NATIVE_INCLUDE_EDM_LOG_H
#define COMMON_NATIVE_INCLUDE_EDM_LOG_H

#include "hilog/log.h"

#ifndef LOG_DOMAIN_EDM
#define LOG_DOMAIN_EDM 0xD001E00
#endif

#ifndef LOG_TAG_EDM
#define LOG_TAG_EDM "EDM"
#endif

namespace OHOS {
namespace EDM {

#ifndef EDMLOGD
#define EDMLOGD(...) HILOG_IMPL(LOG_CORE, LOG_DEBUG, LOG_DOMAIN_EDM, LOG_TAG_EDM, __VA_ARGS__)
#endif

#ifndef EDMLOGE
#define EDMLOGE(...) HILOG_IMPL(LOG_CORE, LOG_ERROR, LOG_DOMAIN_EDM, LOG_TAG_EDM, __VA_ARGS__)
#endif

#ifndef EDMLOGF
#define EDMLOGF(...) HILOG_IMPL(LOG_CORE, LOG_FATAL, LOG_DOMAIN_EDM, LOG_TAG_EDM, __VA_ARGS__)
#endif

#ifndef EDMLOGI
#define EDMLOGI(...) HILOG_IMPL(LOG_CORE, LOG_INFO, LOG_DOMAIN_EDM, LOG_TAG_EDM, __VA_ARGS__)
#endif

#ifndef EDMLOGW
#define EDMLOGW(...) HILOG_IMPL(LOG_CORE, LOG_WARN, LOG_DOMAIN_EDM, LOG_TAG_EDM, __VA_ARGS__)
#endif
} // namespace EDM
} // namespace OHOS
#endif // COMMON_NATIVE_INCLUDE_EDM_LOG_H
