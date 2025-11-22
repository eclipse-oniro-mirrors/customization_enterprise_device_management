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

#ifndef EDM_TOOLS_EDM_INCLUDE_ICOMMAND_H
#define EDM_TOOLS_EDM_INCLUDE_ICOMMAND_H

#include <edm_errors.h>

#include <memory>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace OHOS {
namespace EDM {

class ICommand {
public:
    explicit ICommand(std::string name)
        : name_(std::move(name))
    {}
    virtual ~ICommand() = default;
    virtual ErrCode Execute() = 0;
    [[nodiscard]] virtual std::string GetUsage() const = 0;
    [[nodiscard]] virtual std::string GetName() const;

protected:
    bool ValidateUniqueOption(char opt);

private:
    std::string name_;
    std::unordered_set<int> usedOptions_;
};

using CommandPtr = std::unique_ptr<ICommand>;

} // namespace EDM
} // namespace OHOS

#endif // EDM_TOOLS_EDM_INCLUDE_ICOMMAND_H
