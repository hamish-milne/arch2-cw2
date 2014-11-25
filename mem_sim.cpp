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

bool read_write_memory(cache* my_cache, uint32_t addr, uint8_t* data, bool write)
{
	uint32_t i, block, endblock;
	if(!ensure_mem_capacity(my_cache, addr + 1))
		return false;
	/// Align to block
	block = my_cache->bytes_word * my_cache->words_block;
	endblock = addr + my_cache->bytes_word;
	addr -= addr % block;
	endblock -= endblock % block;
	for(; addr <= endblock; addr += block)
		for(i = 0; i < block; i++)
			if(write)
				my_cache->memory_space[addr + i] = data[i];
			else
				data[i] = my_cache->memory_space[addr + i];
	return true;
}

uint8_t* get_tmp_block(cache* my_cache)
{
	static uint8_t tmp = NULL;
	static uint32_t length = 0;
	uint32_t new_length = my_cache->bytes_word * my_cache->words_block * 2;
	if(new_length > length)
		tmp = realloc(tmp, new_length);
	return tmp;
}

bool read_cache(cache* my_cache, uint32_t addr, uint8_t* out, uint32_t* time)
{
	uint8_t *sets_start, *tmp, *data;
	cache_item *items_start, *lru_item;
	uint64_t lru_timestamp;
	/// Find all the offsets, index and tag
	uint32_t byte_offset, index, tag, i, row_size, lru_index;
	tag = addr;
	byte_offset = tag % (my_cache->bytes_word * my_cache->words_block);
	tag -= byte_offset;
	//word_offset = tag % my_cache->words_block;
	//tag -= word_offset;
	index = tag % my_cache->blocks_set;
	tag /= my_cache->bytes_word * my_cache->words_block * my_cache->blocks_set;

	/// Now look in all the cache sets and see if it's valid
	row_size = my_cache->words_block * my_cache->bytes_word;
	items_start = my_cache->metadata + (index * my_cache->sets_cache);
	data_start = my_cache->cache_space + (index * my_cache->sets_cache * row_size);
	lru_index = my_cache->sets_cache;
	lru_timestamp = -1;
	for(i = 0; i < my_cache->sets_cache; i++)
	{
		/// If it's invalid, we should use this set to store
		if(!items_start[i].valid)
		{
			lru_index = i;
			lru_timestamp = 0;
		} else
		{
			/// Otherwise, it might contain the value we want, or maybe not
			if(items_start[i].tag == tag)
				break;
			else if(items_start[i].timestamp < lru_timestamp)
			{
				lru_timestamp = items_start[i].timestamp;
				lru_index = i;
			}
		}
	}

	if(i >= my_cache->sets_cache)
	{
		/// Miss! Find a cache item to evict..
		if(lru_index >= my_cache->sets_cache)
		{
			last_error = "Internal error (LRU item not found)";
			return false;
		}
		lru_item = items_start + lru_index;
		data = data_start + (lru_index * row_size);
		/// We're doing write-back, so if the item is valid and dirty, write it back
		if(lru_item->valid && lru_item->dirty)
		{
			if(!read_write_memory(my_cache,
				lru_item->tag * my_cache->bytes_word * my_cache->words_block, data, true))
				return false;
			*time += my_cache->memory_write_time;
		}
		/// Now read from memory into the cache item
		if(!read_write_memory(my_cache, addr, data, false))
			return false;
		*time += my_cache->memory_read_time;
		i = lru_index;
	}

	/// Hit! Copy a single word to the output
	*time += my_cache->hit_time;


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
