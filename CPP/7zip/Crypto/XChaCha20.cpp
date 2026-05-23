// XChaCha20.cpp

#include "StdAfx.h"

#include "../../../C/CpuArch.h"

#include "../../Common/ComTry.h"

#ifndef Z7_ST
#include "../../Windows/Synchronization.h"
#endif

#include "../Common/StreamUtils.h"

#include "XChaCha20.h"

#ifndef Z7_EXTRACT_ONLY
#include "RandGen.h"
#endif

#ifdef MY_CPU_X86_OR_AMD64
#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__GNUC__)
#include <x86intrin.h>
#endif
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

#ifdef MY_CPU_X86_OR_AMD64

#ifdef MY_CPU_SSE2

namespace {

template <unsigned int R>
Z7_FORCE_INLINE __m128i RotateLeft_SSE2(const __m128i val)
{
  return _mm_or_si128(_mm_slli_epi32(val, R), _mm_srli_epi32(val, 32 - R));
}

template <>
Z7_FORCE_INLINE __m128i RotateLeft_SSE2<8>(const __m128i val)
{
#ifdef __SSSE3__
  const __m128i mask = _mm_set_epi8(14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3);
  return _mm_shuffle_epi8(val, mask);
#else
  return _mm_or_si128(_mm_slli_epi32(val, 8), _mm_srli_epi32(val, 24));
#endif
}

template <>
Z7_FORCE_INLINE __m128i RotateLeft_SSE2<16>(const __m128i val)
{
#ifdef __SSSE3__
  const __m128i mask = _mm_set_epi8(13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2);
  return _mm_shuffle_epi8(val, mask);
#else
  return _mm_or_si128(_mm_slli_epi32(val, 16), _mm_srli_epi32(val, 16));
#endif
}

#define SSE2_QUARTERROUND(a, b, c, d) \
  a = _mm_add_epi32(a, b); \
  d = _mm_xor_si128(d, a); \
  d = RotateLeft_SSE2<16>(d); \
  c = _mm_add_epi32(c, d); \
  b = _mm_xor_si128(b, c); \
  b = RotateLeft_SSE2<12>(b); \
  a = _mm_add_epi32(a, b); \
  d = _mm_xor_si128(d, a); \
  d = RotateLeft_SSE2<8>(d); \
  c = _mm_add_epi32(c, d); \
  b = _mm_xor_si128(b, c); \
  b = RotateLeft_SSE2<7>(b);

Z7_NO_INLINE void ChaCha20_OperateKeystream_SSE2(
    const UInt32 *state,
    const Byte *input,
    Byte *output)
{
  const __m128i state0 = _mm_loadu_si128((const __m128i *)(state + 0));
  const __m128i state1 = _mm_loadu_si128((const __m128i *)(state + 4));
  const __m128i state2 = _mm_loadu_si128((const __m128i *)(state + 8));
  const __m128i state3 = _mm_loadu_si128((const __m128i *)(state + 12));

  __m128i r0_0 = state0;
  __m128i r0_1 = state1;
  __m128i r0_2 = state2;
  __m128i r0_3 = state3;

  __m128i r1_0 = state0;
  __m128i r1_1 = state1;
  __m128i r1_2 = state2;
  __m128i r1_3 = _mm_add_epi64(state3, _mm_set_epi32(0, 0, 0, 1));

  __m128i r2_0 = state0;
  __m128i r2_1 = state1;
  __m128i r2_2 = state2;
  __m128i r2_3 = _mm_add_epi64(state3, _mm_set_epi32(0, 0, 0, 2));

  __m128i r3_0 = state0;
  __m128i r3_1 = state1;
  __m128i r3_2 = state2;
  __m128i r3_3 = _mm_add_epi64(state3, _mm_set_epi32(0, 0, 0, 3));

  for (int i = 0; i < 10; i++)
  {
    SSE2_QUARTERROUND(r0_0, r0_1, r0_2, r0_3);
    SSE2_QUARTERROUND(r1_0, r1_1, r1_2, r1_3);
    SSE2_QUARTERROUND(r2_0, r2_1, r2_2, r2_3);
    SSE2_QUARTERROUND(r3_0, r3_1, r3_2, r3_3);

    r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(0, 3, 2, 1));
    r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
    r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(2, 1, 0, 3));

    r1_1 = _mm_shuffle_epi32(r1_1, _MM_SHUFFLE(0, 3, 2, 1));
    r1_2 = _mm_shuffle_epi32(r1_2, _MM_SHUFFLE(1, 0, 3, 2));
    r1_3 = _mm_shuffle_epi32(r1_3, _MM_SHUFFLE(2, 1, 0, 3));

    r2_1 = _mm_shuffle_epi32(r2_1, _MM_SHUFFLE(0, 3, 2, 1));
    r2_2 = _mm_shuffle_epi32(r2_2, _MM_SHUFFLE(1, 0, 3, 2));
    r2_3 = _mm_shuffle_epi32(r2_3, _MM_SHUFFLE(2, 1, 0, 3));

    r3_1 = _mm_shuffle_epi32(r3_1, _MM_SHUFFLE(0, 3, 2, 1));
    r3_2 = _mm_shuffle_epi32(r3_2, _MM_SHUFFLE(1, 0, 3, 2));
    r3_3 = _mm_shuffle_epi32(r3_3, _MM_SHUFFLE(2, 1, 0, 3));

    SSE2_QUARTERROUND(r0_0, r0_1, r0_2, r0_3);
    SSE2_QUARTERROUND(r1_0, r1_1, r1_2, r1_3);
    SSE2_QUARTERROUND(r2_0, r2_1, r2_2, r2_3);
    SSE2_QUARTERROUND(r3_0, r3_1, r3_2, r3_3);

    r0_1 = _mm_shuffle_epi32(r0_1, _MM_SHUFFLE(2, 1, 0, 3));
    r0_2 = _mm_shuffle_epi32(r0_2, _MM_SHUFFLE(1, 0, 3, 2));
    r0_3 = _mm_shuffle_epi32(r0_3, _MM_SHUFFLE(0, 3, 2, 1));

    r1_1 = _mm_shuffle_epi32(r1_1, _MM_SHUFFLE(2, 1, 0, 3));
    r1_2 = _mm_shuffle_epi32(r1_2, _MM_SHUFFLE(1, 0, 3, 2));
    r1_3 = _mm_shuffle_epi32(r1_3, _MM_SHUFFLE(0, 3, 2, 1));

    r2_1 = _mm_shuffle_epi32(r2_1, _MM_SHUFFLE(2, 1, 0, 3));
    r2_2 = _mm_shuffle_epi32(r2_2, _MM_SHUFFLE(1, 0, 3, 2));
    r2_3 = _mm_shuffle_epi32(r2_3, _MM_SHUFFLE(0, 3, 2, 1));

    r3_1 = _mm_shuffle_epi32(r3_1, _MM_SHUFFLE(2, 1, 0, 3));
    r3_2 = _mm_shuffle_epi32(r3_2, _MM_SHUFFLE(1, 0, 3, 2));
    r3_3 = _mm_shuffle_epi32(r3_3, _MM_SHUFFLE(0, 3, 2, 1));
  }

  r0_0 = _mm_add_epi32(r0_0, state0);
  r0_1 = _mm_add_epi32(r0_1, state1);
  r0_2 = _mm_add_epi32(r0_2, state2);
  r0_3 = _mm_add_epi32(r0_3, state3);

  r1_0 = _mm_add_epi32(r1_0, state0);
  r1_1 = _mm_add_epi32(r1_1, state1);
  r1_2 = _mm_add_epi32(r1_2, state2);
  r1_3 = _mm_add_epi32(r1_3, state3);
  r1_3 = _mm_add_epi64(r1_3, _mm_set_epi32(0, 0, 0, 1));

  r2_0 = _mm_add_epi32(r2_0, state0);
  r2_1 = _mm_add_epi32(r2_1, state1);
  r2_2 = _mm_add_epi32(r2_2, state2);
  r2_3 = _mm_add_epi32(r2_3, state3);
  r2_3 = _mm_add_epi64(r2_3, _mm_set_epi32(0, 0, 0, 2));

  r3_0 = _mm_add_epi32(r3_0, state0);
  r3_1 = _mm_add_epi32(r3_1, state1);
  r3_2 = _mm_add_epi32(r3_2, state2);
  r3_3 = _mm_add_epi32(r3_3, state3);
  r3_3 = _mm_add_epi64(r3_3, _mm_set_epi32(0, 0, 0, 3));

  if (input)
  {
    r0_0 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 0*16)), r0_0);
    r0_1 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 1*16)), r0_1);
    r0_2 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 2*16)), r0_2);
    r0_3 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 3*16)), r0_3);
  }

  _mm_storeu_si128((__m128i *)(output + 0*16), r0_0);
  _mm_storeu_si128((__m128i *)(output + 1*16), r0_1);
  _mm_storeu_si128((__m128i *)(output + 2*16), r0_2);
  _mm_storeu_si128((__m128i *)(output + 3*16), r0_3);

  if (input)
  {
    r1_0 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 4*16)), r1_0);
    r1_1 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 5*16)), r1_1);
    r1_2 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 6*16)), r1_2);
    r1_3 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 7*16)), r1_3);
  }

  _mm_storeu_si128((__m128i *)(output + 4*16), r1_0);
  _mm_storeu_si128((__m128i *)(output + 5*16), r1_1);
  _mm_storeu_si128((__m128i *)(output + 6*16), r1_2);
  _mm_storeu_si128((__m128i *)(output + 7*16), r1_3);

  if (input)
  {
    r2_0 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 8*16)), r2_0);
    r2_1 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 9*16)), r2_1);
    r2_2 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 10*16)), r2_2);
    r2_3 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 11*16)), r2_3);
  }

  _mm_storeu_si128((__m128i *)(output + 8*16), r2_0);
  _mm_storeu_si128((__m128i *)(output + 9*16), r2_1);
  _mm_storeu_si128((__m128i *)(output + 10*16), r2_2);
  _mm_storeu_si128((__m128i *)(output + 11*16), r2_3);

  if (input)
  {
    r3_0 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 12*16)), r3_0);
    r3_1 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 13*16)), r3_1);
    r3_2 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 14*16)), r3_2);
    r3_3 = _mm_xor_si128(_mm_loadu_si128((const __m128i *)(input + 15*16)), r3_3);
  }

  _mm_storeu_si128((__m128i *)(output + 12*16), r3_0);
  _mm_storeu_si128((__m128i *)(output + 13*16), r3_1);
  _mm_storeu_si128((__m128i *)(output + 14*16), r3_2);
  _mm_storeu_si128((__m128i *)(output + 15*16), r3_3);
}

#ifdef MY_CPU_AMD64

template <unsigned int R>
Z7_FORCE_INLINE __m256i RotateLeft_AVX2(const __m256i val)
{
  return _mm256_or_si256(_mm256_slli_epi32(val, R), _mm256_srli_epi32(val, 32 - R));
}

template <>
Z7_FORCE_INLINE __m256i RotateLeft_AVX2<8>(const __m256i val)
{
  const __m256i mask = _mm256_set_epi8(
    14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3,
    14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3);
  return _mm256_shuffle_epi8(val, mask);
}

template <>
Z7_FORCE_INLINE __m256i RotateLeft_AVX2<16>(const __m256i val)
{
  const __m256i mask = _mm256_set_epi8(
    13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2,
    13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2);
  return _mm256_shuffle_epi8(val, mask);
}

#define AVX2_QUARTERROUND(a, b, c, d) \
  a = _mm256_add_epi32(a, b); \
  d = _mm256_xor_si256(d, a); \
  d = RotateLeft_AVX2<16>(d); \
  c = _mm256_add_epi32(c, d); \
  b = _mm256_xor_si256(b, c); \
  b = RotateLeft_AVX2<12>(b); \
  a = _mm256_add_epi32(a, b); \
  d = _mm256_xor_si256(d, a); \
  d = RotateLeft_AVX2<8>(d); \
  c = _mm256_add_epi32(c, d); \
  b = _mm256_xor_si256(b, c); \
  b = RotateLeft_AVX2<7>(b);

Z7_NO_INLINE void ChaCha20_OperateKeystream_AVX2(
    const UInt32 *state,
    const Byte *input,
    Byte *output)
{
  const __m256i state0 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)(state + 0)));
  const __m256i state1 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)(state + 4)));
  const __m256i state2 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)(state + 8)));
  const __m256i state3 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i *)(state + 12)));

  const UInt32 C = 0xFFFFFFFFu - state[12];
  const __m256i CTR0 = _mm256_set_epi32(0, 0,     0, 0, 0, 0, C < 4, 4);
  const __m256i CTR1 = _mm256_set_epi32(0, 0, C < 1, 1, 0, 0, C < 5, 5);
  const __m256i CTR2 = _mm256_set_epi32(0, 0, C < 2, 2, 0, 0, C < 6, 6);
  const __m256i CTR3 = _mm256_set_epi32(0, 0, C < 3, 3, 0, 0, C < 7, 7);

  __m256i X0_0 = state0;
  __m256i X0_1 = state1;
  __m256i X0_2 = state2;
  __m256i X0_3 = _mm256_add_epi32(state3, CTR0);

  __m256i X1_0 = state0;
  __m256i X1_1 = state1;
  __m256i X1_2 = state2;
  __m256i X1_3 = _mm256_add_epi32(state3, CTR1);

  __m256i X2_0 = state0;
  __m256i X2_1 = state1;
  __m256i X2_2 = state2;
  __m256i X2_3 = _mm256_add_epi32(state3, CTR2);

  __m256i X3_0 = state0;
  __m256i X3_1 = state1;
  __m256i X3_2 = state2;
  __m256i X3_3 = _mm256_add_epi32(state3, CTR3);

  for (int i = 0; i < 10; i++)
  {
    AVX2_QUARTERROUND(X0_0, X0_1, X0_2, X0_3);
    AVX2_QUARTERROUND(X1_0, X1_1, X1_2, X1_3);
    AVX2_QUARTERROUND(X2_0, X2_1, X2_2, X2_3);
    AVX2_QUARTERROUND(X3_0, X3_1, X3_2, X3_3);

    X0_1 = _mm256_shuffle_epi32(X0_1, _MM_SHUFFLE(0, 3, 2, 1));
    X0_2 = _mm256_shuffle_epi32(X0_2, _MM_SHUFFLE(1, 0, 3, 2));
    X0_3 = _mm256_shuffle_epi32(X0_3, _MM_SHUFFLE(2, 1, 0, 3));

    X1_1 = _mm256_shuffle_epi32(X1_1, _MM_SHUFFLE(0, 3, 2, 1));
    X1_2 = _mm256_shuffle_epi32(X1_2, _MM_SHUFFLE(1, 0, 3, 2));
    X1_3 = _mm256_shuffle_epi32(X1_3, _MM_SHUFFLE(2, 1, 0, 3));

    X2_1 = _mm256_shuffle_epi32(X2_1, _MM_SHUFFLE(0, 3, 2, 1));
    X2_2 = _mm256_shuffle_epi32(X2_2, _MM_SHUFFLE(1, 0, 3, 2));
    X2_3 = _mm256_shuffle_epi32(X2_3, _MM_SHUFFLE(2, 1, 0, 3));

    X3_1 = _mm256_shuffle_epi32(X3_1, _MM_SHUFFLE(0, 3, 2, 1));
    X3_2 = _mm256_shuffle_epi32(X3_2, _MM_SHUFFLE(1, 0, 3, 2));
    X3_3 = _mm256_shuffle_epi32(X3_3, _MM_SHUFFLE(2, 1, 0, 3));

    AVX2_QUARTERROUND(X0_0, X0_1, X0_2, X0_3);
    AVX2_QUARTERROUND(X1_0, X1_1, X1_2, X1_3);
    AVX2_QUARTERROUND(X2_0, X2_1, X2_2, X2_3);
    AVX2_QUARTERROUND(X3_0, X3_1, X3_2, X3_3);

    X0_1 = _mm256_shuffle_epi32(X0_1, _MM_SHUFFLE(2, 1, 0, 3));
    X0_2 = _mm256_shuffle_epi32(X0_2, _MM_SHUFFLE(1, 0, 3, 2));
    X0_3 = _mm256_shuffle_epi32(X0_3, _MM_SHUFFLE(0, 3, 2, 1));

    X1_1 = _mm256_shuffle_epi32(X1_1, _MM_SHUFFLE(2, 1, 0, 3));
    X1_2 = _mm256_shuffle_epi32(X1_2, _MM_SHUFFLE(1, 0, 3, 2));
    X1_3 = _mm256_shuffle_epi32(X1_3, _MM_SHUFFLE(0, 3, 2, 1));

    X2_1 = _mm256_shuffle_epi32(X2_1, _MM_SHUFFLE(2, 1, 0, 3));
    X2_2 = _mm256_shuffle_epi32(X2_2, _MM_SHUFFLE(1, 0, 3, 2));
    X2_3 = _mm256_shuffle_epi32(X2_3, _MM_SHUFFLE(0, 3, 2, 1));

    X3_1 = _mm256_shuffle_epi32(X3_1, _MM_SHUFFLE(2, 1, 0, 3));
    X3_2 = _mm256_shuffle_epi32(X3_2, _MM_SHUFFLE(1, 0, 3, 2));
    X3_3 = _mm256_shuffle_epi32(X3_3, _MM_SHUFFLE(0, 3, 2, 1));
  }

  X0_0 = _mm256_add_epi32(X0_0, state0);
  X0_1 = _mm256_add_epi32(X0_1, state1);
  X0_2 = _mm256_add_epi32(X0_2, state2);
  X0_3 = _mm256_add_epi32(X0_3, state3);
  X0_3 = _mm256_add_epi32(X0_3, CTR0);

  X1_0 = _mm256_add_epi32(X1_0, state0);
  X1_1 = _mm256_add_epi32(X1_1, state1);
  X1_2 = _mm256_add_epi32(X1_2, state2);
  X1_3 = _mm256_add_epi32(X1_3, state3);
  X1_3 = _mm256_add_epi32(X1_3, CTR1);

  X2_0 = _mm256_add_epi32(X2_0, state0);
  X2_1 = _mm256_add_epi32(X2_1, state1);
  X2_2 = _mm256_add_epi32(X2_2, state2);
  X2_3 = _mm256_add_epi32(X2_3, state3);
  X2_3 = _mm256_add_epi32(X2_3, CTR2);

  X3_0 = _mm256_add_epi32(X3_0, state0);
  X3_1 = _mm256_add_epi32(X3_1, state1);
  X3_2 = _mm256_add_epi32(X3_2, state2);
  X3_3 = _mm256_add_epi32(X3_3, state3);
  X3_3 = _mm256_add_epi32(X3_3, CTR3);

  if (input)
  {
    _mm256_storeu_si256((__m256i *)(output + 0*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X0_0, X0_1, 1 + (3 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 0*32))));
    _mm256_storeu_si256((__m256i *)(output + 1*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X0_2, X0_3, 1 + (3 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 1*32))));
    _mm256_storeu_si256((__m256i *)(output + 2*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X1_0, X1_1, 1 + (3 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 2*32))));
    _mm256_storeu_si256((__m256i *)(output + 3*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X1_2, X1_3, 1 + (3 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 3*32))));
  }
  else
  {
    _mm256_storeu_si256((__m256i *)(output + 0*32),
      _mm256_permute2x128_si256(X0_0, X0_1, 1 + (3 << 4)));
    _mm256_storeu_si256((__m256i *)(output + 1*32),
      _mm256_permute2x128_si256(X0_2, X0_3, 1 + (3 << 4)));
    _mm256_storeu_si256((__m256i *)(output + 2*32),
      _mm256_permute2x128_si256(X1_0, X1_1, 1 + (3 << 4)));
    _mm256_storeu_si256((__m256i *)(output + 3*32),
      _mm256_permute2x128_si256(X1_2, X1_3, 1 + (3 << 4)));
  }

  if (input)
  {
    _mm256_storeu_si256((__m256i *)(output + 4*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X2_0, X2_1, 1 + (3 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 4*32))));
    _mm256_storeu_si256((__m256i *)(output + 5*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X2_2, X2_3, 1 + (3 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 5*32))));
    _mm256_storeu_si256((__m256i *)(output + 6*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X3_0, X3_1, 1 + (3 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 6*32))));
    _mm256_storeu_si256((__m256i *)(output + 7*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X3_2, X3_3, 1 + (3 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 7*32))));
  }
  else
  {
    _mm256_storeu_si256((__m256i *)(output + 4*32),
      _mm256_permute2x128_si256(X2_0, X2_1, 1 + (3 << 4)));
    _mm256_storeu_si256((__m256i *)(output + 5*32),
      _mm256_permute2x128_si256(X2_2, X2_3, 1 + (3 << 4)));
    _mm256_storeu_si256((__m256i *)(output + 6*32),
      _mm256_permute2x128_si256(X3_0, X3_1, 1 + (3 << 4)));
    _mm256_storeu_si256((__m256i *)(output + 7*32),
      _mm256_permute2x128_si256(X3_2, X3_3, 1 + (3 << 4)));
  }

  if (input)
  {
    _mm256_storeu_si256((__m256i *)(output + 8*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X0_0, X0_1, 0 + (2 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 8*32))));
    _mm256_storeu_si256((__m256i *)(output + 9*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X0_2, X0_3, 0 + (2 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 9*32))));
    _mm256_storeu_si256((__m256i *)(output + 10*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X1_0, X1_1, 0 + (2 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 10*32))));
    _mm256_storeu_si256((__m256i *)(output + 11*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X1_2, X1_3, 0 + (2 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 11*32))));
  }
  else
  {
    _mm256_storeu_si256((__m256i *)(output + 8*32),
      _mm256_permute2x128_si256(X0_0, X0_1, 0 + (2 << 4)));
    _mm256_storeu_si256((__m256i *)(output + 9*32),
      _mm256_permute2x128_si256(X0_2, X0_3, 0 + (2 << 4)));
    _mm256_storeu_si256((__m256i *)(output + 10*32),
      _mm256_permute2x128_si256(X1_0, X1_1, 0 + (2 << 4)));
    _mm256_storeu_si256((__m256i *)(output + 11*32),
      _mm256_permute2x128_si256(X1_2, X1_3, 0 + (2 << 4)));
  }

  if (input)
  {
    _mm256_storeu_si256((__m256i *)(output + 12*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X2_0, X2_1, 0 + (2 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 12*32))));
    _mm256_storeu_si256((__m256i *)(output + 13*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X2_2, X2_3, 0 + (2 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 13*32))));
    _mm256_storeu_si256((__m256i *)(output + 14*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X3_0, X3_1, 0 + (2 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 14*32))));
    _mm256_storeu_si256((__m256i *)(output + 15*32),
      _mm256_xor_si256(_mm256_permute2x128_si256(X3_2, X3_3, 0 + (2 << 4)),
      _mm256_loadu_si256((const __m256i *)(input + 15*32))));
  }
  else
  {
    _mm256_storeu_si256((__m256i *)(output + 12*32),
      _mm256_permute2x128_si256(X2_0, X2_1, 0 + (2 << 4)));
    _mm256_storeu_si256((__m256i *)(output + 13*32),
      _mm256_permute2x128_si256(X2_2, X2_3, 0 + (2 << 4)));
    _mm256_storeu_si256((__m256i *)(output + 14*32),
      _mm256_permute2x128_si256(X3_0, X3_1, 0 + (2 << 4)));
    _mm256_storeu_si256((__m256i *)(output + 15*32),
      _mm256_permute2x128_si256(X3_2, X3_3, 0 + (2 << 4)));
  }

  _mm256_zeroupper();
}

#endif

}

static bool g_SSE2Enabled = false;
static bool g_AVX2Enabled = false;
static bool g_SIMDInitialized = false;

static void InitSIMD()
{
  if (g_SIMDInitialized)
    return;
  g_SIMDInitialized = true;
  
#ifdef MY_CPU_AMD64
  g_SSE2Enabled = true;
  g_AVX2Enabled = CPU_IsSupported_AVX2() != 0;
#elif defined(MY_CPU_X86)
  g_SSE2Enabled = CPU_IsSupported_SSE2() != 0;
#endif
}

#endif

#endif

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
