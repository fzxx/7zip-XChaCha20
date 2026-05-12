// XChaCha20.cpp

#include "StdAfx.h"

#include "../../../C/CpuArch.h"
#include "../../../C/Sha256.h"

#include "../../Common/ComTry.h"
#include "../../Common/MyBuffer2.h"

#ifndef Z7_ST
#include "../../Windows/Synchronization.h"
#endif

#include "../Common/StreamUtils.h"

#include "XChaCha20.h"

#ifndef Z7_EXTRACT_ONLY
#include "RandGen.h"
#endif

namespace NCrypto {
namespace NXChaCha20 {

static const unsigned k_NumCyclesPower_Supported_MAX = 24;

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) \
  a += b; d ^= a; d = ROTL32(d, 16); \
  c += d; b ^= c; b = ROTL32(b, 12); \
  a += b; d ^= a; d = ROTL32(d, 8); \
  c += d; b ^= c; b = ROTL32(b, 7);

static bool ConstantTimeCompare(const Byte *a, const Byte *b, size_t size)
{
  volatile Byte result = 0;
  for (size_t i = 0; i < size; i++)
    result |= a[i] ^ b[i];
  return result == 0;
}

bool CKeyInfo::IsEqualTo(const CKeyInfo &a) const
{
  if (SaltSize != a.SaltSize || NumCyclesPower != a.NumCyclesPower)
    return false;
  if (!ConstantTimeCompare(Salt, a.Salt, SaltSize))
    return false;
  if (Password.Size() != a.Password.Size())
    return false;
  return ConstantTimeCompare(Password, a.Password, Password.Size());
}

void CKeyInfo::CalcKey()
{
  if (NumCyclesPower == 0x3F)
  {
    unsigned pos;
    for (pos = 0; pos < SaltSize; pos++)
      Key[pos] = Salt[pos];
    for (unsigned i = 0; i < Password.Size() && pos < kKeySize; i++)
      Key[pos++] = Password[i];
    for (; pos < kKeySize; pos++)
      Key[pos] = 0;
  }
  else
  {
    const unsigned kUnrPow = 6;
    const UInt32 numUnroll = (UInt32)1 << (NumCyclesPower <= kUnrPow ? (unsigned)NumCyclesPower : kUnrPow);

    const size_t bufSize = 8 + SaltSize + Password.Size();
    const size_t unrollSize = bufSize * numUnroll;

    const size_t shaAllocSize = sizeof(CSha256) + unrollSize + bufSize * 2;
    CAlignedBuffer1 sha(shaAllocSize);
    Byte *buf = sha + sizeof(CSha256);

    memcpy(buf, Salt, SaltSize);
    memcpy(buf + SaltSize, Password, Password.Size());
    memset(buf + bufSize - 8, 0, 8);
    
    Sha256_Init((CSha256 *)(void *)(Byte *)sha);
    
    {
      {
        Byte *dest = buf;
        for (UInt32 i = 1; i < numUnroll; i++)
        {
          dest += bufSize;
          memcpy(dest, buf, bufSize);
        }
      }

      const UInt32 numRounds = (UInt32)1 << NumCyclesPower;
      UInt32 r = 0;
      do
      {
        Byte *dest = buf + bufSize - 8;
        UInt32 i = r;
        r += numUnroll;
        do
        {
          SetUi32(dest, i)  i++; dest += bufSize;
        }
        while (i < r);
        Sha256_Update((CSha256 *)(void *)(Byte *)sha, buf, unrollSize);
      }
      while (r < numRounds);
    }

    Sha256_Final((CSha256 *)(void *)(Byte *)sha, Key);
    memset(sha, 0, shaAllocSize);
  }
}

bool CKeyInfoCache::GetKey(CKeyInfo &key)
{
  FOR_VECTOR (i, Keys)
  {
    const CKeyInfo &cached = Keys[i];
    if (key.IsEqualTo(cached))
    {
      for (unsigned j = 0; j < kKeySize; j++)
        key.Key[j] = cached.Key[j];
      if (i != 0)
        Keys.MoveToFront(i);
      return true;
    }
  }
  return false;
}

void CKeyInfoCache::FindAndAdd(const CKeyInfo &key)
{
  FOR_VECTOR (i, Keys)
  {
    const CKeyInfo &cached = Keys[i];
    if (key.IsEqualTo(cached))
    {
      if (i != 0)
        Keys.MoveToFront(i);
      return;
    }
  }
  Add(key);
}

void CKeyInfoCache::Add(const CKeyInfo &key)
{
  if (Keys.Size() >= Size)
    Keys.DeleteBack();
  Keys.Insert(0, key);
}

static CKeyInfoCache g_GlobalKeyCache(32);

#ifndef Z7_ST
  static NWindows::NSynchronization::CCriticalSection g_GlobalKeyCacheCriticalSection;
  #define MT_LOCK NWindows::NSynchronization::CCriticalSectionLock lock(g_GlobalKeyCacheCriticalSection);
#else
  #define MT_LOCK
#endif

CBase::CBase():
  _cachedKeys(16),
  _counter(0)
{
  for (unsigned i = 0; i < sizeof(_nonce); i++)
    _nonce[i] = 0;
}

void CBaseCoder::DeriveKey()
{
  HChaCha20Block(_derivedKey, _key.Key, _nonce);
  _derivedKeyValid = true;
}

void CBase::PrepareKey()
{
  MT_LOCK
  
  bool finded = false;
  if (!_cachedKeys.GetKey(_key))
  {
    finded = g_GlobalKeyCache.GetKey(_key);
    if (!finded)
      _key.CalcKey();
    _cachedKeys.Add(_key);
  }
  if (!finded)
    g_GlobalKeyCache.FindAndAdd(_key);
}

static const Byte kSigma[16] = {
  'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'
};

void CBaseCoder::HChaCha20Block(Byte *output, const Byte *key, const Byte *nonce)
{
  UInt32 x0, x1, x2, x3, x4, x5, x6, x7;
  UInt32 x8, x9, x10, x11, x12, x13, x14, x15;
  
  x0 = GetUi32(kSigma);
  x1 = GetUi32(kSigma + 4);
  x2 = GetUi32(kSigma + 8);
  x3 = GetUi32(kSigma + 12);
  
  x4 = GetUi32(key);
  x5 = GetUi32(key + 4);
  x6 = GetUi32(key + 8);
  x7 = GetUi32(key + 12);
  x8 = GetUi32(key + 16);
  x9 = GetUi32(key + 20);
  x10 = GetUi32(key + 24);
  x11 = GetUi32(key + 28);
  
  x12 = GetUi32(nonce);
  x13 = GetUi32(nonce + 4);
  x14 = GetUi32(nonce + 8);
  x15 = GetUi32(nonce + 12);
  
#define DOUBLE_ROUND \
  QUARTERROUND(x0, x4, x8,  x12); \
  QUARTERROUND(x1, x5, x9,  x13); \
  QUARTERROUND(x2, x6, x10, x14); \
  QUARTERROUND(x3, x7, x11, x15); \
  QUARTERROUND(x0, x5, x10, x15); \
  QUARTERROUND(x1, x6, x11, x12); \
  QUARTERROUND(x2, x7, x8,  x13); \
  QUARTERROUND(x3, x4, x9,  x14);
  
  DOUBLE_ROUND; DOUBLE_ROUND;
  DOUBLE_ROUND; DOUBLE_ROUND;
  DOUBLE_ROUND; DOUBLE_ROUND;
  DOUBLE_ROUND; DOUBLE_ROUND;
  DOUBLE_ROUND; DOUBLE_ROUND;
  
#undef DOUBLE_ROUND
  
  SetUi32(output, x0);
  SetUi32(output + 4, x1);
  SetUi32(output + 8, x2);
  SetUi32(output + 12, x3);
  SetUi32(output + 16, x12);
  SetUi32(output + 20, x13);
  SetUi32(output + 24, x14);
  SetUi32(output + 28, x15);
}

void CBaseCoder::Chacha20Block(Byte *output, const Byte *key, const Byte *nonce, UInt64 counter)
{
  UInt32 x0, x1, x2, x3, x4, x5, x6, x7;
  UInt32 x8, x9, x10, x11, x12, x13, x14, x15;
  
  x0 = GetUi32(kSigma);
  x1 = GetUi32(kSigma + 4);
  x2 = GetUi32(kSigma + 8);
  x3 = GetUi32(kSigma + 12);
  
  x4 = GetUi32(key);
  x5 = GetUi32(key + 4);
  x6 = GetUi32(key + 8);
  x7 = GetUi32(key + 12);
  x8 = GetUi32(key + 16);
  x9 = GetUi32(key + 20);
  x10 = GetUi32(key + 24);
  x11 = GetUi32(key + 28);
  
  x12 = (UInt32)(counter & 0xFFFFFFFF);
  x13 = (UInt32)(counter >> 32);
  x14 = GetUi32(nonce);
  x15 = GetUi32(nonce + 4);
  
#define DOUBLE_ROUND \
  QUARTERROUND(x0, x4, x8,  x12); \
  QUARTERROUND(x1, x5, x9,  x13); \
  QUARTERROUND(x2, x6, x10, x14); \
  QUARTERROUND(x3, x7, x11, x15); \
  QUARTERROUND(x0, x5, x10, x15); \
  QUARTERROUND(x1, x6, x11, x12); \
  QUARTERROUND(x2, x7, x8,  x13); \
  QUARTERROUND(x3, x4, x9,  x14);
  
  DOUBLE_ROUND; DOUBLE_ROUND;
  DOUBLE_ROUND; DOUBLE_ROUND;
  DOUBLE_ROUND; DOUBLE_ROUND;
  DOUBLE_ROUND; DOUBLE_ROUND;
  DOUBLE_ROUND; DOUBLE_ROUND;
  
#undef DOUBLE_ROUND
  
  x0 += GetUi32(kSigma);
  x1 += GetUi32(kSigma + 4);
  x2 += GetUi32(kSigma + 8);
  x3 += GetUi32(kSigma + 12);
  x4 += GetUi32(key);
  x5 += GetUi32(key + 4);
  x6 += GetUi32(key + 8);
  x7 += GetUi32(key + 12);
  x8 += GetUi32(key + 16);
  x9 += GetUi32(key + 20);
  x10 += GetUi32(key + 24);
  x11 += GetUi32(key + 28);
  x12 += (UInt32)(counter & 0xFFFFFFFF);
  x13 += (UInt32)(counter >> 32);
  x14 += GetUi32(nonce);
  x15 += GetUi32(nonce + 4);
  
  SetUi32(output, x0)
  SetUi32(output + 4, x1)
  SetUi32(output + 8, x2)
  SetUi32(output + 12, x3)
  SetUi32(output + 16, x4)
  SetUi32(output + 20, x5)
  SetUi32(output + 24, x6)
  SetUi32(output + 28, x7)
  SetUi32(output + 32, x8)
  SetUi32(output + 36, x9)
  SetUi32(output + 40, x10)
  SetUi32(output + 44, x11)
  SetUi32(output + 48, x12)
  SetUi32(output + 52, x13)
  SetUi32(output + 56, x14)
  SetUi32(output + 60, x15)
}

void CBaseCoder::ProcessData(Byte *data, UInt32 size)
{
  if (!_derivedKeyValid)
  {
    DeriveKey();
  }
  
  while (size > 0)
  {
    if (_blockPos == 0 || _blockPos >= kBlockSize)
    {
      Chacha20Block(_block, _derivedKey, _nonce + 16, _counter);
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

#ifndef Z7_EXTRACT_ONLY

Z7_COM7F_IMF(CEncoder::ResetInitVector())
{
  for (unsigned i = 0; i < sizeof(_nonce); i++)
    _nonce[i] = 0;
  MY_RAND_GEN(_nonce, kNonceSize);
  _counter = 0;
  _blockPos = kBlockSize;
  _derivedKeyValid = false;
  return S_OK;
}

Z7_COM7F_IMF(CEncoder::WriteCoderProperties(ISequentialOutStream *outStream))
{
  Byte props[2 + sizeof(_key.Salt) + kNonceSize];
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
        ((_key.SaltSize == 0 ? 0 : _key.SaltSize - 1) << 4)
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

  return WriteStream(outStream, props, propsSize);
}

CEncoder::CEncoder()
{
  _key.NumCyclesPower = 19;
  _counter = 0;
  _blockPos = kBlockSize;
  _derivedKeyValid = false;
}

#endif

CDecoder::CDecoder()
{
  _counter = 0;
  _blockPos = kBlockSize;
  _derivedKeyValid = false;
}

Z7_COM7F_IMF(CDecoder::SetDecoderProperties2(const Byte *data, UInt32 size))
{
  _key.ClearProps();
 
  _counter = 0;
  _blockPos = kBlockSize;
  _derivedKeyValid = false;
  unsigned i;
  for (i = 0; i < sizeof(_nonce); i++)
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
  
  if (size != 2 + saltSize + nonceSize)
    return E_INVALIDARG;
  _key.SaltSize = saltSize;
  data += 2;
  for (i = 0; i < saltSize; i++)
    _key.Salt[i] = *data++;
  for (i = 0; i < nonceSize && i < kNonceSize; i++)
    _nonce[i] = *data++;
  
  return (_key.NumCyclesPower <= k_NumCyclesPower_Supported_MAX
      || _key.NumCyclesPower == 0x3F) ? S_OK : E_NOTIMPL;
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
  _counter = 0;
  _blockPos = kBlockSize;
  _derivedKeyValid = false;
  return S_OK;
  
  COM_TRY_END
}

Z7_COM7F_IMF2(UInt32, CBaseCoder::Filter(Byte *data, UInt32 size))
{
  ProcessData(data, size);
  return size;
}

}}
