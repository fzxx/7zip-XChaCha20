// XChaCha20Register.cpp

#include "StdAfx.h"

#include "../Common/RegisterCodec.h"

#include "XChaCha20.h"

namespace NCrypto {
namespace NXChaCha20 {

REGISTER_FILTER_E(XChaCha20,
    CDecoder,
    CEncoder,
    0x6F10702, "XChaCha20")

}}
