// XChaCha20Poly1305.cpp

#include "StdAfx.h"

#include "../../../C/CpuArch.h"

#include "../../Common/ComTry.h"

#ifndef Z7_ST
#include "../../Windows/Synchronization.h"
#endif

#include "../Common/StreamUtils.h"

#include "XChaCha20Poly1305.h"

#ifndef Z7_EXTRACT_ONLY
#include "RandGen.h"
#endif

#include "ChaCha20Simd.h"

namespace NCrypto {
namespace NXChaCha20Poly1305 {

void CBaseCoder::ComputePolyKey()
{
  Byte polyBlock[64];
  NXChaCha20::XChaCha20Block_Core(polyBlock, _derivedKey, _nonce + 16, 0);
  memcpy(_polyKey, polyBlock, kPolyKeySize);
  Z7_memset_0_ARRAY(polyBlock);
}

CPoly1305::CPoly1305()
{
  Reset();
}

void CPoly1305::Reset()
{
  memset(_r, 0, sizeof(_r));
  memset(_s, 0, sizeof(_s));
  memset(_h, 0, sizeof(_h));
  memset(_block, 0, sizeof(_block));
  _blockPos = 0;
  _totalLen = 0;
  memset(_aadBlock, 0, sizeof(_aadBlock));
  _aadBlockPos = 0;
  _aadLen = 0;
  _finalized = false;
}

void CPoly1305::SetKey(const Byte *key)
{
  memcpy(_r, key, 16);
  _r[3] &= 15;
  _r[7] &= 15;
  _r[11] &= 15;
  _r[15] &= 15;
  _r[4] &= 252;
  _r[8] &= 252;
  _r[12] &= 252;

  memcpy(_s, key + 16, 16);

  memset(_h, 0, sizeof(_h));
  _blockPos = 0;
  _totalLen = 0;
  _aadBlockPos = 0;
  _aadLen = 0;
  _finalized = false;
}

static void Poly1305_ProcessBlock(Byte h[16], const Byte r[16], const Byte block[16], bool hasHighBit)
{
  UInt64 d[8] = { 0 };
  UInt64 c;

  for (unsigned i = 0; i < 3; i++)
  {
    d[i] = (UInt64)GetUi32(h + i * 4);
  }
  d[3] = ((UInt64)GetUi32(h + 12)) & 0x3FFFFFF;

  for (unsigned i = 0; i < 3; i++)
  {
    UInt64 t = GetUi32(block + i * 4);
    d[i] += t;
  }
  d[3] += ((UInt64)GetUi32(block + 12)) & 0x3FFFFFF;

  if (hasHighBit)
    d[3] |= 0x1000000;

  UInt64 rr[4];
  rr[0] = GetUi32(r) & 0x3FFFFFF;
  rr[1] = ((UInt64)GetUi32(r + 3) >> 2) & 0x3FFFF03;
  rr[2] = ((UInt64)GetUi32(r + 6) >> 4) & 0x3FFC0FF;
  rr[3] = ((UInt64)GetUi32(r + 9) >> 6) & 0x3F03FFF;

  UInt64 m[8] = { 0 };
  for (unsigned i = 0; i < 4; i++)
  {
    for (unsigned j = 0; j < 4; j++)
    {
      m[i + j] += d[i] * rr[j];
    }
  }

  c = m[0] >> 26; m[0] &= 0x3FFFFFF;
  m[1] += c;
  c = m[1] >> 26; m[1] &= 0x3FFFFFF;
  m[2] += c; c = m[2] >> 26; m[2] &= 0x3FFFFFF;
  m[3] += c; c = m[3] >> 26; m[3] &= 0x3FFFFFF;
  m[4] += c; c = m[4] >> 26; m[4] &= 0x3FFFFFF;
  m[5] += c; c = m[5] >> 26; m[5] &= 0x3FFFFFF;
  m[6] += c; c = m[6] >> 26; m[6] &= 0x3FFFFFF;
  m[7] += c;

  c = (m[3] >> 26); m[3] &= 0x3FFFFFF;
  m[4] += c;

  m[0] += (m[4] >> 26) * 5; m[4] &= 0x3FFFFFF;
  m[1] += (m[5] >> 26) * 5; m[5] &= 0x3FFFFFF;
  m[2] += (m[6] >> 26) * 5; m[6] &= 0x3FFFFFF;
  m[3] += (m[7] >> 26) * 5; m[7] &= 0x3FFFFFF;

  c = m[0] >> 26; m[0] &= 0x3FFFFFF;
  m[1] += c;
  c = m[1] >> 26; m[1] &= 0x3FFFFFF;
  m[2] += c; c = m[2] >> 26; m[2] &= 0x3FFFFFF;
  m[3] += c; c = m[3] >> 26; m[3] &= 0x3FFFFFF;

  m[0] += (m[3] >> 26) * 5; m[3] &= 0x3FFFFFF;

  c = m[0] >> 26; m[0] &= 0x3FFFFFF;
  m[1] += c;

  SetUi32(h, (UInt32)((m[0]) | (m[1] << 26)));
  SetUi32(h + 4, (UInt32)((m[1] >> 6) | (m[2] << 20)));
  SetUi32(h + 8, (UInt32)((m[2] >> 12) | (m[3] << 14)));
  SetUi32(h + 12, (UInt32)((m[3] >> 18) | (m[4] << 8)));
}

void CPoly1305::Update(const Byte *data, UInt32 size)
{
  if (_finalized)
    return;
  _totalLen += size;

  if (_blockPos > 0)
  {
    unsigned n = 16 - _blockPos;
    if (n > size) n = size;
    memcpy(_block + _blockPos, data, n);
    _blockPos += n;
    data += n;
    size -= n;
    if (_blockPos == 16)
    {
      Poly1305_ProcessBlock(_h, _r, _block, true);
      _blockPos = 0;
    }
  }

  while (size >= 16)
  {
    Poly1305_ProcessBlock(_h, _r, data, true);
    data += 16;
    size -= 16;
  }

  if (size > 0)
  {
    memcpy(_block, data, size);
    _blockPos = size;
  }
}

void CPoly1305::UpdateAad(const Byte *data, UInt32 size)
{
  if (_finalized)
    return;
  _aadLen += size;

  if (_aadBlockPos > 0)
  {
    unsigned n = 16 - _aadBlockPos;
    if (n > size) n = size;
    memcpy(_aadBlock + _aadBlockPos, data, n);
    _aadBlockPos += n;
    data += n;
    size -= n;
    if (_aadBlockPos == 16)
    {
      Poly1305_ProcessBlock(_h, _r, _aadBlock, true);
      _aadBlockPos = 0;
    }
  }

  while (size >= 16)
  {
    Poly1305_ProcessBlock(_h, _r, data, true);
    data += 16;
    size -= 16;
  }

  if (size > 0)
  {
    memcpy(_aadBlock, data, size);
    _aadBlockPos = size;
  }
}

void CPoly1305::Final(Byte *tag)
{
  if (_finalized)
    return;
  _finalized = true;

  unsigned aadLenMod = (unsigned)(_aadLen & 0xF);
  if (aadLenMod != 0)
  {
    unsigned padLen = 16 - aadLenMod;
    memset(_aadBlock + _aadBlockPos, 0, padLen);
    Poly1305_ProcessBlock(_h, _r, _aadBlock, true);
  }

  unsigned ctLenMod = (unsigned)(_totalLen & 0xF);

  if (ctLenMod != 0)
  {
    unsigned padLen = 16 - ctLenMod;
    memset(_block + _blockPos, 0, padLen);
    Poly1305_ProcessBlock(_h, _r, _block, true);
  }

  {
    Byte lenBlock[16];
    for (unsigned i = 0; i < 8; i++)
      lenBlock[i] = (Byte)(_aadLen >> (i * 8));
    for (unsigned i = 0; i < 8; i++)
      lenBlock[8 + i] = (Byte)(_totalLen >> (i * 8));
    Poly1305_ProcessBlock(_h, _r, lenBlock, true);
  }

  UInt64 h0 = (UInt64)GetUi32(_h);
  UInt64 h1 = (UInt64)GetUi32(_h + 4);
  UInt64 h2 = (UInt64)GetUi32(_h + 8);
  UInt64 h3 = (UInt64)GetUi32(_h + 12) & 0x3FFFFFF;

  UInt64 s0 = (UInt64)GetUi32(_s);
  UInt64 s1 = (UInt64)GetUi32(_s + 4);
  UInt64 s2 = (UInt64)GetUi32(_s + 8);
  UInt64 s3 = (UInt64)GetUi32(_s + 12);

  h0 += s0;
  UInt64 c = h0 >> 26; h0 &= 0x3FFFFFF;
  h1 += s1 + c; c = h1 >> 26; h1 &= 0x3FFFFFF;
  h2 += s2 + c; c = h2 >> 26; h2 &= 0x3FFFFFF;
  h3 += s3 + c;

  UInt64 g0, g1, g2, g3;
  g0 = h0 + 5;
  c = g0 >> 26; g0 &= 0x3FFFFFF;
  g1 = h1 + c; c = g1 >> 26; g1 &= 0x3FFFFFF;
  g2 = h2 + c; c = g2 >> 26; g2 &= 0x3FFFFFF;
  g3 = h3 + c - 4;

  UInt64 mask = (g3 >> 63) - 1;
  h0 = (h0 & ~mask) | (g0 & mask);
  h1 = (h1 & ~mask) | (g1 & mask);
  h2 = (h2 & ~mask) | (g2 & mask);
  h3 = (h3 & ~mask) | (g3 & mask);

  SetUi32(tag, (UInt32)(h0 | (h1 << 26)));
  SetUi32(tag + 4, (UInt32)((h1 >> 6) | (h2 << 20)));
  SetUi32(tag + 8, (UInt32)((h2 >> 12) | (h3 << 14)));
  SetUi32(tag + 12, (UInt32)(h3 >> 18));
}

void CBaseCoder::DeriveKey()
{
  NXChaCha20::XHChaCha20Block_Core(_derivedKey, _key.Key, _nonce);
  ComputePolyKey();
  _poly1305.SetKey(_polyKey);
  if (_aadSize > 0)
  {
    _poly1305.UpdateAad(_aad, _aadSize);
  }
  _derivedKeyValid = true;
}

void CBaseCoder::ProcessData(Byte *data, UInt32 size)
{
  if (!_derivedKeyValid)
  {
    DeriveKey();
  }

#ifdef MY_CPU_X86_OR_AMD64
#ifdef MY_CPU_SSE2
  InitSIMD();

  if (size >= kBlockSize * 4)
  {
    UInt32 state[16];
    state[0] = GetUi32(kSigma);
    state[1] = GetUi32(kSigma + 4);
    state[2] = GetUi32(kSigma + 8);
    state[3] = GetUi32(kSigma + 12);
    state[4] = GetUi32(_derivedKey);
    state[5] = GetUi32(_derivedKey + 4);
    state[6] = GetUi32(_derivedKey + 8);
    state[7] = GetUi32(_derivedKey + 12);
    state[8] = GetUi32(_derivedKey + 16);
    state[9] = GetUi32(_derivedKey + 20);
    state[10] = GetUi32(_derivedKey + 24);
    state[11] = GetUi32(_derivedKey + 28);
    state[12] = (UInt32)(_counter & 0xFFFFFFFF);
    state[13] = (UInt32)(_counter >> 32);
    state[14] = GetUi32(_nonce + 16);
    state[15] = GetUi32(_nonce + 20);

#ifdef MY_CPU_AMD64
    if (g_AVX2Enabled && size >= kBlockSize * 8)
    {
      while (size >= kBlockSize * 8)
      {
        ChaCha20_OperateKeystream_AVX2(state, data, data);
        state[12] += 8;
        if (state[12] < 8)
          state[13]++;
        data += kBlockSize * 8;
        size -= kBlockSize * 8;
      }
    }
#endif

    if (g_SSE2Enabled && size >= kBlockSize * 4)
    {
      while (size >= kBlockSize * 4)
      {
        ChaCha20_OperateKeystream_SSE2(state, data, data);
        state[12] += 4;
        if (state[12] < 4)
          state[13]++;
        data += kBlockSize * 4;
        size -= kBlockSize * 4;
      }
    }

    _counter = (UInt64)state[13] << 32 | state[12];
  }
#endif
#endif

  while (size > 0)
  {
    if (_blockPos == 0 || _blockPos >= kBlockSize)
    {
      NXChaCha20::XChaCha20Block_Core(_block, _derivedKey, _nonce + 16, _counter);
      _blockPos = 0;
      _counter++;
      if (_counter == 0)
      {
        memset(_block, 0, kBlockSize);
      }
    }

    UInt32 remaining = kBlockSize - _blockPos;
    UInt32 toProcess = (size < remaining) ? size : remaining;

    Byte *dataPtr = data;
    const Byte *blockPtr = _block + _blockPos;
    UInt32 count = toProcess;

#ifdef MY_CPU_64BIT
    while (count >= 8)
    {
      *(UInt64 *)dataPtr ^= *(const UInt64 *)blockPtr;
      dataPtr += 8;
      blockPtr += 8;
      count -= 8;
    }
#endif

    while (count >= 4)
    {
      *(UInt32 *)dataPtr ^= *(const UInt32 *)blockPtr;
      dataPtr += 4;
      blockPtr += 4;
      count -= 4;
    }

    while (count--)
      *dataPtr++ ^= *blockPtr++;

    data += toProcess;
    size -= toProcess;
    _blockPos += toProcess;
  }
}

Z7_COM7F_IMF(CBaseCoder::CryptoSetPassword(const Byte *data, UInt32 size))
{
  COM_TRY_BEGIN

  _key.Password.Wipe();
  _key.Password.CopyFrom(data, (size_t)size);
  _derivedKeyValid = false;
  return S_OK;

  COM_TRY_END
}

Z7_COM7F_IMF(CBaseCoder::Init())
{
  COM_TRY_BEGIN

  PrepareKey();
  _counter = 1;
  _blockPos = kBlockSize;
  _derivedKeyValid = false;
  _poly1305.Reset();

  return S_OK;

  COM_TRY_END
}

#ifndef Z7_EXTRACT_ONLY

Z7_COM7F_IMF(CEncoder::ResetInitVector())
{
  for (unsigned i = 0; i < sizeof(_nonce); i++)
    _nonce[i] = 0;
  MY_RAND_GEN(_nonce, kNonceSize);
  _counter = 1;
  _blockPos = kBlockSize;
  _derivedKeyValid = false;
  _poly1305.Reset();

  _aadSize = 1;
  const unsigned nonceSizeMinus1 = kNonceSize - 1;
  const unsigned nonceHigh = (nonceSizeMinus1 >= 16) ? (1 << 6) : 0;
  const unsigned nonceLow = nonceSizeMinus1 & 0x0F;
  _aad[0] = (Byte)(_key.NumCyclesPower
      | (_key.SaltSize == 0 ? 0 : (1 << 7))
      | nonceHigh);
  if (_key.SaltSize != 0)
  {
    _aad[1] = (Byte)(((_key.SaltSize - 1) << 4) | nonceLow);
    memcpy(_aad + 2, _key.Salt, _key.SaltSize);
    _aadSize = 2 + _key.SaltSize;
    memcpy(_aad + _aadSize, _nonce, kNonceSize);
    _aadSize += kNonceSize;
  }
  else
  {
    _aad[1] = (Byte)(nonceLow);
    _aadSize = 2;
    memcpy(_aad + _aadSize, _nonce, kNonceSize);
    _aadSize += kNonceSize;
  }

  _tagReady = false;
  memset(_computedTag, 0, kTagSize);
  return S_OK;
}

Z7_COM7F_IMF2(UInt32, CEncoder::Filter(Byte *data, UInt32 size))
{
  ProcessData(data, size);
  _poly1305.Update(data, size);
  return size;
}

Z7_COM7F_IMF(CEncoder::WriteCoderProperties(ISequentialOutStream *outStream))
{
  Byte props[2 + sizeof(_key.Salt) + kNonceSize + kTagSize];
  unsigned propsSize = 1;

  const unsigned nonceSizeMinus1 = kNonceSize - 1;
  const unsigned nonceHigh = (nonceSizeMinus1 >= 16) ? (1 << 6) : 0;
  const unsigned nonceLow = nonceSizeMinus1 & 0x0F;

  props[0] = (Byte)(_key.NumCyclesPower
      | (_key.SaltSize == 0 ? 0 : (1 << 7))
      | nonceHigh);

  if (_key.SaltSize != 0)
  {
    props[1] = (Byte)(
        ((_key.SaltSize - 1) << 4)
        | nonceLow);
    memcpy(props + 2, _key.Salt, _key.SaltSize);
    propsSize = 2 + _key.SaltSize;
    memcpy(props + propsSize, _nonce, kNonceSize);
    propsSize += kNonceSize;
  }
  else
  {
    props[1] = (Byte)(nonceLow);
    propsSize = 2;
    memcpy(props + propsSize, _nonce, kNonceSize);
    propsSize += kNonceSize;
  }

  if (!_tagReady)
  {
    _poly1305.Final(_computedTag);
    _tagReady = true;
  }

  memcpy(props + propsSize, _computedTag, kTagSize);
  propsSize += kTagSize;

  return WriteStream(outStream, props, propsSize);
}

CEncoder::CEncoder()
{
  _key.NumCyclesPower = 19;
  _counter = 1;
  _blockPos = kBlockSize;
  _derivedKeyValid = false;
  _aadSize = 0;
  _tagReady = false;
  memset(_computedTag, 0, kTagSize);
}

#endif

CDecoder::CDecoder()
{
  _counter = 1;
  _blockPos = kBlockSize;
  _derivedKeyValid = false;
  _aadSize = 0;
  _authChecked = false;
  _authResult = 0;
  memset(_expectedTag, 0, kTagSize);
}

Z7_COM7F_IMF2(UInt32, CDecoder::Filter(Byte *data, UInt32 size))
{
  if (!_derivedKeyValid)
    DeriveKey();
  _poly1305.Update(data, size);
  ProcessData(data, size);
  return size;
}

Z7_COM7F_IMF(CDecoder::SetDecoderProperties2(const Byte *data, UInt32 size))
{
  _key.ClearProps();

  _counter = 1;
  _blockPos = kBlockSize;
  _derivedKeyValid = false;
  _poly1305.Reset();
  _authChecked = false;
  _authResult = 0;
  memset(_expectedTag, 0, kTagSize);

  for (unsigned i = 0; i < sizeof(_nonce); i++)
    _nonce[i] = 0;

  if (size == 0)
    return S_OK;

  const unsigned b0 = data[0];
  _key.NumCyclesPower = b0 & 0x3F;
  if ((b0 & 0xC0) == 0)
    return size == 1 ? S_OK : E_INVALIDARG;
  if (size <= 1)
    return E_INVALIDARG;

  const unsigned b1 = data[1];
  const unsigned saltSize = ((b0 >> 7) & 1) + (b1 >> 4);
  const unsigned nonceSizeMinus1 = ((b0 >> 6) & 1) * 16 + (b1 & 0x0F);
  const unsigned nonceSize = nonceSizeMinus1 + 1;

  const unsigned totalSize = 2 + saltSize + nonceSize + kTagSize;

  if (size != totalSize)
  {
    return E_INVALIDARG;
  }

  _aadSize = totalSize - kTagSize;
  memcpy(_aad, data, _aadSize);

  _key.SaltSize = saltSize;
  data += 2;
  for (unsigned i = 0; i < saltSize; i++)
    _key.Salt[i] = *data++;
  for (unsigned i = 0; i < nonceSize && i < kNonceSize; i++)
    _nonce[i] = *data++;

  memcpy(_expectedTag, data, kTagSize);

  return (_key.NumCyclesPower <= k_NumCyclesPower_Supported_MAX
      || _key.NumCyclesPower == 0x3F) ? S_OK : E_NOTIMPL;
}

Z7_COM7F_IMF(CDecoder::CryptoAuthVerify(Int32 *result))
{
  if (_authChecked)
  {
    *result = _authResult;
    return S_OK;
  }
  _authChecked = true;

  Byte computedTag[kTagSize];
  _poly1305.Final(computedTag);

  _authResult = (memcmp(computedTag, _expectedTag, kTagSize) == 0) ? 0 : 1;
  *result = _authResult;

  Z7_memset_0_ARRAY(computedTag);
  return S_OK;
}

}} // namespace NCrypto::NXChaCha20Poly1305