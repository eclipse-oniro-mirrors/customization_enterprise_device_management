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

#include "edm_permission.h"
#include "string_ex.h"

namespace OHOS {
namespace EDM {
EdmPermission::EdmPermission() {}
EdmPermission::~EdmPermission() {}

EdmPermission::EdmPermission(const std::string &name, const uint32_t &type)
    : permissionName_(name), adminType_(type)
{}

const std::string &EdmPermission::getPermissionName() const
{
    return permissionName_;
}

void EdmPermission::setPermissionName(const std::string &permissionName)
{
    EdmPermission::permissionName_ = permissionName;
}

uint32_t EdmPermission::getAdminType() const
{
    return adminType_;
}

void EdmPermission::setAdminType(uint32_t adminType)
{
    EdmPermission::adminType_ = adminType;
}

bool EdmPermission::operator == (const EdmPermission &permission) const
{
    return (permissionName_ == permission.getPermissionName() && adminType_ == permission.getAdminType());
}

bool EdmPermission::ReadFromParcel(Parcel &parcel)
{
    permissionName_ = Str16ToStr8(parcel.ReadString16());
    adminType_ = parcel.ReadUint32();
    return true;
}

bool EdmPermission::Marshalling(Parcel &parcel) const
{
    parcel.WriteString16(Str8ToStr16(permissionName_));
    parcel.WriteUint32(adminType_);
    return true;
}

EdmPermission *EdmPermission::Unmarshalling(Parcel &parcel)
{
    auto *permission = new (std::nothrow)EdmPermission();
    permission->ReadFromParcel(parcel);
    return permission;
}
} // namespace EDM
} // namespace OHOS