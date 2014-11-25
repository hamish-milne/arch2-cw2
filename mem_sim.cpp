#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define N_COMMANDS 5
#define MAX_SIZE 0x800000
#define NUM_PARAMS 8
#define WARNING "# Warning: "
#define ERROR "# Error: "
#define BUF_SIZE 1024

typedef bool (command*)(cache* my_cache, char* line);

#ifndef __cplusplus
typedef enum
{
	true = 1,
	false = 0
} bool;
#endif // __cplusplus

typedef struct
{
	bool valid, dirty;
	uint32_t tag;
	uint64_t timestamp;
} cache_item;

typedef struct
{
	uint8_t* memory_space;
	uint8_t* cache_space;
	cache_item* metadata;
	uint32_t memory_size;
	uint32_t address_bits;
	uint32_t bytes_word;
	uint32_t words_block;
	uint32_t blocks_set;
	uint32_t sets_cache;
	uint32_t hit_time;
	uint32_t memory_read_time;
	uint32_t memory_write_time;
} cache;

static char* last_error = NULL;

bool streq(const char* a, const char* b)
{
	while(*a && *b)
		if(*(a++) != *(b++))
			return false;
	return true;
}

void print_error()
{
	if(last_error != NULL)
		printf(ERROR "%s\n", last_error);
	last_error = NULL;
}

void print_warning(const char* warning)
{
	printf(WARNING "%s\n", warning);
}

static bool create_cache(cache* my_cache)
{
	if(my_cache->address_bits > 32)
	{
		last_error = "Too many address bits. Maximum is 32";
		return false;
	}
	my_cache->memory_space = NULL;
	my_cache->cache_space = calloc(
		my_cache->words_block *
		my_cache->blocks_set *
		my_cache->sets_cache,
		my_cache->bytes_word
		);
	if(!my_cache->cache_space)
	{
		last_error = "Out of memory (cache space)";
		return false;
	}
	my_cache->metadata = calloc(
		my_cache->blocks_set *
		my_cache->sets_cache,
		sizeof(cache_item)
		);
	if(!my_cache->metadata)
	{
		last_error = "Out of memory (cache metadata)";
		return false;
	}
	return true;
}

bool ensure_mem_capacity(cache* my_cache, uint32_t length)
{
	uint32_t block, remainder, i;
	if(length > MAX_SIZE)
	{
		last_error = "Address out of range";
		return false;
	}
	if(my_cache->memory_space == NULL || my_cache->memory_size < length)
	{
		block = my_cache->bytes_word * my_cache->words_block;
		remainder = length % block;
		if(remainder) length += (block - remainder);
		if(my_cache->memory_space == NULL)
			my_cache->memory_space = malloc(length);
		else
			my_cache->memory_space = realloc(my_cache->memory_space, length);
		if(my_cache->memory_space == NULL)
		{
			last_error = "Out of memory (main memory space)";
			print_error();
			exit();
			return false;
		}
		for(i = my_cache->memory_size; i < length; i++)
			my_cache->memory_space[i] = 0;
	}
	return true;
}

bool read_memory(cache* my_cache, uint32_t addr, uint8_t* out)
{
	uint32_t i, block;
	if(!ensure_mem_capacity(my_cache, addr + 1))
		return false;
	/// Align to block
	block = my_cache->bytes_word * my_cache->words_block;
	addr -= addr % block;
	for(i = 0; i < block; i++)
		out[i] = my_cache->memory_space[addr + i];
	return true;
}

bool read_addr(cache* my_cache, uint32_t addr, uint8_t* out, bool* hit)
{
	uint8_t* sets_start;
	cache_item* items_start;
	/// Find all the offsets, index and tag
	uint32_t byte_offset, word_offset, index, tag, i, row_size, lru_index;
	tag = addr;
	byte_offset = tag % my_cache->bytes_word;
	tag -= byte_offset;
	word_offset = tag % my_cache->words_block;
	tag -= word_offset;
	index = tag % my_cache->blocks_set;
	tag /= my_cache->bytes_word * my_cache->words_block * my_cache->blocks_set;

	/// Now look in all the cache sets and see if it's valid
	row_size = my_cache->words_block * my_cache->bytes_word;
	items_start = my_cache->metadata + (index * my_cache->sets_cache);
	sets_start = my_cache->cache_space + (index * my_cache->sets_cache * row_size);
	for(i = 0; i < my_cache->sets_cache; i++)
		if(sets_start[i].valid && sets_start[i].tag == tag)
			break;

	if(i >= my_cache->sets_cache)
	{
		/// Miss!
	}
	else
	{
		/// Hit!
	}
}

static bool read_req(cache* my_cache, char* line)
{

}

static bool comment(cache* my_cache, char* line)
{
}

static const
struct { char* name; command cmd; }
commands[N_COMMANDS] =
{
	{ "#", &comment },
	{ "read-req", &read_req },
	{ "write-req", &write_req },
	{ "flush-req", &flush_req },
	{ "debug-req", &debug_req }
};

static const uint32_t default_values[] =
{
	8,	/// Address bits
	2,	/// Bytes/word
	2,	/// Word/block
	1,	/// Blocks/set
	2,	/// Sets/cache
	1,	/// Cache hit time
	2,	/// Memory read time
	2	/// Memory write time
};

int main(int argc, char* argv[])
{
	cache my_cache;
	uint32_t tmp, position, i;
	uint32_t* start_params = &my_cache.address_bits;
	char buffer[BUF_SIZE], command[BUF_SIZE];
	command cmd;
	for(i = 0; i < NUM_PARAMS; i++)
	{
		if(i+1 < argc)
		{
			printf(WARNING "Parameter %d unset; assuming %d\n", i + 1, default_values[i]);
			*(start_params + i) = default_values[i];
		}
		else
		{
			tmp = strtol(argv[i + 1], NULL, 0);
			if(!tmp || tmp < 0)
			{
				printf(ERROR "Parameter %d is invalid; assuming %d\n", i + 1, default_values[i]);
				*(start_params + i) = default_values[i];
			}
			else
			{
				*(start_params + i) = tmp;
			}
		}
	}
	if(argc > (NUM_PARAMS + 1))
		print_warning("Excess parameters");
	if(create_cache(&cache))
	{
		while(fgets(buffer, BUF_SIZE, stdin))
		{
			if(sscanf(buffer, " %s %n", command, &tmp) < 2)
				continue;
			cmd = NULL;
			for(i = 0; i < N_COMMANDS; i++)
			{
				if(streq(command, commands[i].name))
				{
					cmd = commands[i].cmd;
					break;
				}
			}
			if(!cmd)
				printf(ERROR "Unknown command: %s\n", command)
			else if(!cmd(my_cache, buf + tmp))
				print_error();
		}
	}
	print_error();
	return;
}
