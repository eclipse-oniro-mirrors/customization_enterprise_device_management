/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

EdmPermission::EdmPermission(const std::string &name, AdminType type)
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

AdminType EdmPermission::getAdminType() const
{
    return adminType_;
}

void EdmPermission::setAdminType(AdminType adminType)
{
    EdmPermission::adminType_ = adminType;
}

bool EdmPermission::operator == (const EdmPermission &permission) const
{
    return (permissionName_ == permission.getPermissionName() && adminType_ == permission.getAdminType());
}

bool EdmPermission::ReadFromParcel(MessageParcel &parcel)
{
    permissionName_ = parcel.ReadString();
    int32_t type = parcel.ReadInt32();
    if (type == static_cast<int32_t>(AdminType::NORMAL) || type == static_cast<int32_t>(AdminType::ENT)) {
        adminType_ = static_cast<AdminType>(type);
        return true;
    }
    return false;
}

bool EdmPermission::Marshalling(MessageParcel &parcel) const
{
    parcel.WriteString(permissionName_);
    parcel.WriteInt32(static_cast<int32_t>(adminType_));
    return true;
}

bool EdmPermission::Unmarshalling(MessageParcel &parcel, EdmPermission &edmPermission)
{
    return edmPermission.ReadFromParcel(parcel);
}
} // namespace EDM
} // namespace OHOS