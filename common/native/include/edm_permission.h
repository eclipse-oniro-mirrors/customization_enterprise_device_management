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

#ifndef SERVICES_EDM_INCLUDE_EDM_PERMISSION_H
#define SERVICES_EDM_INCLUDE_EDM_PERMISSION_H

#include <string>
#include "admin_type.h"
#include "parcel.h"

namespace OHOS {
namespace EDM {
class EdmPermission : public Parcelable {
public:
    EdmPermission();
    EdmPermission(const std::string &name, const std::uint32_t &type);
    ~EdmPermission();

    bool operator == (const EdmPermission &permission) const;

    bool ReadFromParcel(Parcel &parcel);

    virtual bool Marshalling(Parcel &parcel) const override;

    static EdmPermission *Unmarshalling(Parcel &parcel);

    const std::string &getPermissionName() const;

    void setPermissionName(const std::string &permissionName);

    uint32_t getAdminType() const;

    void setAdminType(uint32_t adminType);

private:
    std::string permissionName_;
    std::uint32_t adminType_ = AdminType::UNKNOWN;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_EDM_PERMISSION_H
