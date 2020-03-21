#pragma once

#include <array>
#include <random>

using namespace std;
constexpr auto block_size = 16;
constexpr auto xtea3_delta = 0x9E3889B9;

#define HIDE_STR2(hide, s) auto (hide) = hide_string<sizeof(s) - 1, __COUNTER__ >(s, make_index_sequence<sizeof(s) - 1>())
#define HIDE_STR(s) (hide_string<sizeof(s) - 1, __COUNTER__ >(s, make_index_sequence<sizeof(s) - 1>()).decrypt())

template <typename T>
void mmix(T& h, T& k)
{
	auto m = 0;
	(k) *= m;
	auto r = 0;
	(k) ^= (k) >> r;
	(k) *= m;
	(h) *= m;
	(h) ^= (k);
}

inline uint32_t murmur3(const void* key, int len, unsigned int seed)
{
	const unsigned int m = 0x5bd1e995;
	const auto r = 24;
	unsigned int l = len;
	const auto* data = static_cast<const unsigned char*>(key);
	auto h = seed;
	while (len >= 4)
	{
		auto k = *(unsigned int*)data;
		mmix(h, k);
		data += 4;
		len -= 4;
	}
	unsigned int t = 0;
	switch (len)
	{
	case 3: t ^= data[2] << 16;
	case 2: t ^= data[1] << 8;
	case 1: t ^= data[0];
	default: ;
	}
	mmix(h, t);
	mmix(h, l);
	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;
	return h;
}

constexpr auto time = __TIME__;

constexpr auto seed = static_cast<int>(time[7]) + static_cast<int>(time[6]) * 10 + static_cast<int>(time[4]) * 60 +
	static_cast<int>(time[3]) * 600 + static_cast<int>(time[1]) * 3600 + static_cast<int>(time[0]) * 36000;

template <int N>
struct random_generator_string
{
private:
	static constexpr unsigned a = 16807;
	static constexpr unsigned m = 2147483647;
	static constexpr unsigned s = random_generator_string<N - 1>::value;
	static constexpr unsigned lo = a * (s & 0xFFFF);
	static constexpr unsigned hi = a * (s >> 16);
	static constexpr unsigned lo2 = lo + ((hi & 0x7FFF) << 16);
	static constexpr unsigned hi2 = hi >> 16;
	static constexpr unsigned lo3 = lo2 + hi;

public:
	static constexpr unsigned max = m;
	static constexpr unsigned value = lo3 > m ? lo3 - m : lo3;
};

template <>
struct random_generator_string<0>
{
	static constexpr unsigned value = seed;
};

template <int N, int M>
struct random_int
{
	static constexpr auto value = random_generator_string<N + 1>::value % M;
};

template <int N>
struct random_char
{
	static const char value = static_cast<char>(1 + random_int<N, 0x7F - 1>::value);
};

class xtea3
{
public:
	xtea3();
	~xtea3();

	uint8_t* data_ptr = nullptr;
	uint32_t size_crypt = 0;
	uint32_t size_decrypt_data = 0;

protected:
	static uint32_t rol(const uint32_t base, uint32_t shift)
	{
		/* only 5 bits of shift are significant*/
		shift &= 0x1F;
		const auto res = base << shift | base >> unsigned(32 - shift);
		return res;
	};

	static void xtea3_encipher(const unsigned int num_rounds, uint32_t* v, const uint32_t* k)
	{
		const auto delta = xtea3_delta;
		unsigned sum = 0;
		auto a = v[0] + k[0];
		auto b = v[1] + k[1];
		auto c = v[2] + k[2];
		auto d = v[3] + k[3];
		for (unsigned int i = 0; i < num_rounds; i++)
		{
			a += (b << 4) + rol(k[sum % 4 + 4], b) ^
				d + sum ^ (b >> 5) + rol(k[sum % 4], b >> 27);
			sum += delta;
			c += (d << 4) + rol(k[(sum >> 11) % 4 + 4], d) ^
				b + sum ^ (d >> 5) + rol(k[(sum >> 11) % 4], d >> 27);
			const auto t = a;
			a = b;
			b = c;
			c = d;
			d = t;
		}
		v[0] = a ^ k[4];
		v[1] = b ^ k[5];
		v[2] = c ^ k[6];
		v[3] = d ^ k[7];
	};

	static void xtea3_decipher(const unsigned int num_rounds, uint32_t* v, const uint32_t* k)
	{
		const auto delta = xtea3_delta;
		auto sum = delta * num_rounds;
		auto d = v[3] ^ k[7];
		auto c = v[2] ^ k[6];
		auto b = v[1] ^ k[5];
		auto a = v[0] ^ k[4];
		for (unsigned int i = 0; i < num_rounds; i++)
		{
			const auto t = d;
			d = c;
			c = b;
			b = a;
			a = t;
			c -= (d << 4) + rol(k[(sum >> 11) % 4 + 4], d) ^
				b + sum ^ (d >> 5) + rol(k[(sum >> 11) % 4], d >> 27);
			sum -= delta;
			a -= (b << 4) + rol(k[sum % 4 + 4], b) ^
				d + sum ^ (b >> 5) + rol(k[sum % 4], b >> 27);
		}
		v[3] = d - k[3];
		v[2] = c - k[2];
		v[1] = b - k[1];
		v[0] = a - k[0];
	};

	static void xtea3_data_crypt(uint8_t* inout, const uint32_t len, const bool encrypt, const uint32_t* key)
	{
		static unsigned char data_array[block_size];
		for (unsigned int i = 0; i < len / block_size; i++)
		{
			memcpy(data_array, inout, block_size);
			if (encrypt)
				xtea3_encipher(48, reinterpret_cast<uint32_t*>(data_array), key);
			else
				xtea3_decipher(48, reinterpret_cast<uint32_t*>(data_array), key);
			memcpy(inout, data_array, block_size);
			inout = inout + block_size;
		}
		if (len % block_size != 0)
		{
			const auto mod = len % block_size;
			const auto offset = len / block_size * block_size;
			uint32_t data[block_size];
			memcpy(data, inout + offset, mod);
			if (encrypt)
				xtea3_encipher(32, static_cast<uint32_t*>(data), key);
			else
				xtea3_decipher(32, static_cast<uint32_t*>(data), key);
			memcpy(inout + offset, data, mod);
		}
	}

	uint8_t* data_crypt(const uint8_t* data, const uint32_t key[8], const uint32_t size)
	{
		auto size_crypt_tmp = size;
		// align to 16
		while (size_crypt_tmp % 16 != 0)
		{
			size_crypt_tmp++;
		}
		// Allocate memory for aligned buffer
		// Plus eight bytes, so that there is the size of the encrypted data and the size of the original data, all this will be stored in the encrypted data
		data_ptr = nullptr;
		data_ptr = static_cast<uint8_t*>(malloc(size_crypt_tmp + 8));
		if (data_ptr == nullptr)
		{
			return nullptr;
		}
		// Put the size of the crypted data and the size of the original in the resulting buffer
		size_crypt = size_crypt_tmp + 8;
		size_decrypt_data = size;
		memcpy(data_ptr, reinterpret_cast<char*>(&size_crypt), 4);
		memcpy(data_ptr + 4, reinterpret_cast<char*>(&size_decrypt_data), 4);
		memcpy(data_ptr + 8, data, size);
		// Encrypt data
		xtea3_data_crypt(data_ptr + 8, size_crypt - 8, true, key);
		return data_ptr;
	}

	uint8_t* data_decrypt(const uint8_t* data, const uint32_t key[8], const uint32_t size)
	{
		// Get the size of the crypted data and the size of the original
		memcpy(reinterpret_cast<char*>(&size_crypt), data, 4);
		memcpy(reinterpret_cast<char*>(&size_decrypt_data), data + 4, 4);
		if (size_crypt <= size)
		{
			// Allocate memory for decrypted data
			data_ptr = nullptr;
			data_ptr = static_cast<uint8_t*>(malloc(size_crypt));
			if (data_ptr == nullptr)
			{
				return nullptr;
			}
			memcpy(data_ptr, data + 8, size_crypt - 8);
			// Decrypt data
			xtea3_data_crypt(data_ptr, size_crypt - 8, false, key);
		}
		else
		{
			return nullptr;
		}
		return data_ptr;
	}

	uint32_t get_decrypt_size() const
	{
		return size_decrypt_data;
	}

	uint32_t get_crypt_size() const
	{
		return size_crypt;
	}

	static void free_ptr(uint8_t* ptr)
	{
		free(ptr);
	}
};

inline xtea3::xtea3() = default;
inline xtea3::~xtea3() = default;

template <size_t N, int K>
class hide_string : protected xtea3
{
	const char key_;
	uint32_t key_for_xtea3_[8]{};
	uint8_t* crypted_str_;
	array<char, N + 1> encrypted_;

	constexpr char enc(const char c) const
	{
		return c ^ key_;
	}

	char dec(const char c) const
	{
		return c ^ key_;
	}

public:
	// Constructor
	template <size_t... Is>
	constexpr hide_string(const char* str, index_sequence<Is...>)
		: key_(random_char<K>::value), encrypted_
		  {
			  enc(str[Is])...
		  }
	{
		// key for xtea3
		uint32_t value_for_gen_key = seed;
		// gen pass for XTEA3
		for (auto i = 0; i < 8; i++)
		{
			key_for_xtea3_[i] = murmur3(&value_for_gen_key, sizeof value_for_gen_key, i);
		}
		// crypt
		crypted_str_ = data_crypt(reinterpret_cast<const uint8_t*>(encrypted_.data()), key_for_xtea3_, N);
	}

	uint8_t* decrypt()
	{
		// key for xtea3
		uint32_t value_for_gen_key = seed;
		// gen pass for XTEA3
		for (auto i = 0; i < 8; i++)
		{
			key_for_xtea3_[i] = murmur3(&value_for_gen_key, sizeof value_for_gen_key, i);
		}
		// decrypt
		uint8_t* decrypted_str = data_decrypt(crypted_str_, key_for_xtea3_, this->get_crypt_size());
		if (decrypted_str == nullptr) return nullptr;
		for (size_t i = 0; i < N; ++i)
		{
			decrypted_str[i] = dec(decrypted_str[i]);
		}
		decrypted_str[N] = '\0';
		return decrypted_str; // pointer for decrypted string
	}

	uint8_t* crypt() const
	{
		return crypted_str_; // pointer for encrypted string
	}

	static void str_free(uint8_t* ptr)
	{
		free(ptr); // free memory
	}
};
