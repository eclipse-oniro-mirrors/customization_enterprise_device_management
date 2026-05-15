/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "array_usb_device_type_serializer.h"
#include "edm_constants.h"

namespace OHOS {
namespace EDM {
ArrayUsbDeviceTypeSerializer::ArrayUsbDeviceTypeSerializer()
    : ArrayUsbDeviceTypeSerializerBase(0, EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE)
{
}
} // namespace EDM
} // namespace OHOS
