#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#define MAX_SIZE 0x800000
#define BUF_SIZE 1024

#define WARNING "# Warning: "
#define ERROR "# Error: "
#define INFO "# Info: "

#define NUM_COMMANDS 5
#define NUM_PARAMS 8

#define S (char*)
#define U8 (uint8_t*)

#ifndef __cplusplus
typedef enum
{
	true = 1,
	false = 0
} bool;
#endif // __cplusplus

/**
 * All the data required to manage a single cache block
 **/
typedef struct
{
	bool valid, dirty;		/// Valid and dirty flags
	uint32_t tag;			/// The upper address bits
	uint64_t timestamp;		/// The time this block was last accessed
} cache_item;

/**
 * All the data associated with the simulated cache
 **/
typedef struct
{
	uint8_t* memory_space;	/// The main memory data
	uint8_t* cache_space;	/// The cache data
	cache_item* metadata;	/// The cache meta-data
	uint32_t memory_size;	/// The current amount of allocated main memory
	uint32_t address_bits;	/// The number of address bits
	uint32_t bytes_word;	/// The number of bytes in a word
	uint32_t words_block;	/// The number of words in a block
	uint32_t blocks_set;	/// The number of blocks in a cache set
	uint32_t sets_cache;	/// The number of cache sets (associativity)
	uint32_t hit_time;		/// The time taken for a cache hit
	uint32_t memory_read_time;		/// The time for a memory read
	uint32_t memory_write_time;		/// The time for a memory write
} cache;

/**
 * The required signature for an input command
 * Returns true for success, false for failure
 **/
typedef bool (*command)(cache* my_cache,		/// The cache object
                        char* line,				/// The input line
                        uint64_t timestamp);	/// The current timestamp

/**
 * The last reported error, or NULL for no error
 **/
static char* last_error = NULL;

/**
 * Tests whether two strings are equal
 **/
bool streq(const char* a, const char* b)
{
	while(*a || *b)
		if(*(a++) != *(b++))
			return false;
	return true;
}

/**
 * Prints and resets the last error
 **/
void print_error()
{
	if(last_error != NULL)
		printf(ERROR "%s\n", last_error);
	last_error = NULL;
}

/**
 * Prints the given warning
 **/
void print_warning(const char* warning)
{
	printf(WARNING "%s\n", warning);
}

/**
 * Sets up the given cache using its fixed input parameters
 * (address_bits, bytes_word, words_block, blocks_set, sets_cache)
 * Returns true for success, false for failure
 **/
static bool create_cache(cache* my_cache)
{
	if(my_cache->address_bits > 32)
	{
		last_error = S"Too many address bits. Maximum is 32";
		return false;
	}
	my_cache->memory_space = NULL;
	my_cache->memory_size = 0;
	my_cache->cache_space = U8 calloc(
		my_cache->words_block *
		my_cache->blocks_set *
		my_cache->sets_cache,
		my_cache->bytes_word
		);
	if(!my_cache->cache_space)
	{
		last_error = S"Out of memory (cache space)";
		return false;
	}
	my_cache->metadata = (cache_item*)
	calloc(
		my_cache->blocks_set *
		my_cache->sets_cache,
		sizeof(cache_item)
		);
	if(!my_cache->metadata)
	{
		last_error = S"Out of memory (cache metadata)";
		return false;
	}
	return true;
}

/**
 * Reallocates the main memory (if necessary) to ensure it has 'length' bytes
 * Returns true on success, false on failure
 **/
bool ensure_mem_capacity(cache* my_cache, uint32_t length)
{
	uint32_t i;
	if(length > MAX_SIZE)
	{
		last_error = S"Address out of range (memory cannot expand)";
		return false;
	}
	if(my_cache->memory_space == NULL || my_cache->memory_size < length)
	{
		my_cache->memory_space = U8 realloc(my_cache->memory_space, length);
		if(my_cache->memory_space == NULL)
		{
			last_error = S"Out of memory (main memory space)";
			return false;
		}
		for(i = my_cache->memory_size; i < length; i++)
			my_cache->memory_space[i] = 0;
		my_cache->memory_size = length;
	}
	return true;
}

/**
 * Reads or writes from main memory
 * Only deals with a whole block
 * Returns true on success, false on failure
 * 'my_cache', 'data' and 'time' cannot be null
 **/
bool read_write_memory(cache* my_cache,	/// The cache object
                       uint32_t addr,	/// The block-aligned address
                       uint8_t* data,	/// The data to read/write to
                       bool write,		/// Whether we are writing
                       uint32_t* time)	/// Where to write the time taken
{
	uint32_t i, block;
	/// Check block align
	block = my_cache->bytes_word * my_cache->words_block;
	if(!ensure_mem_capacity(my_cache, addr + block))
		return false;
	if(addr % block)
	{
		last_error = S"Internal error (Memory request not block aligned)";
		return false;
	}
	for(i = 0; i < block; i++)
		if(write)
			my_cache->memory_space[addr + i] = data[i];
		else
			data[i] = my_cache->memory_space[addr + i];
	*time += write ? my_cache->memory_write_time : my_cache->memory_read_time;
	return true;
}

/**
 * Gets a temporary buffer that is at least twice the size of a block
 **/
static uint8_t* get_tmp_block(cache* my_cache)
{
	static uint8_t* tmp = NULL;
	static uint32_t length = 0;
	uint32_t new_length = my_cache->bytes_word * my_cache->words_block * 2;
	if(new_length > length)
		tmp = U8 realloc(tmp, new_length);
	/// If no buffer, just exit now.
	/// Rare enough that there's no need for an error
	if(!tmp)
		exit(-1);
	return tmp;
}

/**
 * Reads or writes to the cache, passing it to the main memory if needed
 * Only deals with a whole block
 * Returns true on success, false on failure
 * 'my_cache', 'out', 'time', and 'hit' cannot be null
 **/
bool read_write_cache(cache* my_cache,		/// Cache object
                      uint32_t addr,		/// Block-aligned address
                      uint8_t* out,			/// Data input/output
                      uint32_t* time,		/// Memory time taken
                      uint64_t timestamp,	/// Current time
                      int32_t* set_index,	/// Set index output (or NULL)
                      bool* hit,			/// Hit output
                      bool write)			/// Whether we are writing
{
	uint8_t *data, *data_start;
	cache_item *items_start, *lru_item;
	uint64_t lru_timestamp;
	/// Find the index and tag
	uint32_t index, tag, i, lru_index, block;
	tag = addr;
	block = my_cache->bytes_word * my_cache->words_block;
	if(addr % block)
	{
		last_error = S"Internal error (Cache read request not block aligned)";
		return false;
	}
	tag /= block;
	index = tag % my_cache->blocks_set;
	tag /= my_cache->blocks_set;

	/// Now look in all the cache sets and see if it's valid
	items_start = my_cache->metadata + (index * my_cache->sets_cache);
	data_start = my_cache->cache_space + (index * my_cache->sets_cache * block);
	lru_index = my_cache->sets_cache;
	lru_timestamp = -1;
	for(i = 0; i < my_cache->sets_cache; i++)
	{
		/// If it's invalid, we should use this set to store
		if(!items_start[i].valid)
		{
			/// If we've found a blank space already, don't swap
			if(lru_timestamp)
			{
				lru_index = i;
				lru_timestamp = 0;
			}
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
		*hit = false;
		/// Miss! Find a cache item to evict..
		if(lru_index >= my_cache->sets_cache)
		{
			last_error = S"Internal error (LRU item not found)";
			return false;
		}
		lru_item = items_start + lru_index;
		data = data_start + (lru_index * block);
		/// We're doing write-back, so write back if the item is dirty
		if(lru_item->valid && lru_item->dirty)
		{
			if(!read_write_memory(my_cache,
				(lru_item->tag*my_cache->blocks_set + lru_index)
									* block, data, true, time))
				return false;
		}
		/// Now read from memory into the cache item, unless we're writing
		if(!write && !read_write_memory(my_cache, addr, data, false, time))
			return false;
		/// This is taken from memory, so we know it's clean (and valid)
		lru_item->dirty = false;
		lru_item->valid = true;
		lru_item->tag = tag;
	} else
	{
		*hit &= true;
		lru_index = i;
	}

	/// Hit! Copy a single word either way
	data = data_start + (lru_index * block);
	if(set_index)
		*set_index = lru_index;
	if(write)
	{
		for(i = 0; i < block; i++)
			data[i] = out[i];
		items_start[lru_index].dirty = true;
	} else
	{
		for(i = 0; i < block; i++)
			out[i] = data[i];
	}

	/// And finally set the timestamp of that item
	items_start[lru_index].timestamp = timestamp;
	return true;
}

/**
 * Checks whether the given string pointer has printable data
 * A warning is outputted if it does
 **/
static void check_excess_params(char* line,				/// Pointer to the line
								const char* request)	/// Type of request
{
	while(*line && isspace(*line))
		line++;
	if(*line)
		printf(WARNING "Excess parameters for %s request", request);
}

/**
 * Performs a read or write request
 * Returns true on success, false on failure
 **/
static bool read_write_req(cache* my_cache,		/// Cache object
                           char* line,			/// Text input
                           uint64_t timestamp,	/// Current time
                           bool write)			/// Whether we are writing
{
	static uint8_t* read_buf = NULL;
	static uint32_t read_buf_len = 0;

	int whitespace;
	bool hit, two_blocks;
	char *endptr, *test;
	char data_buf[3];
	int32_t block_offset, set_index;
	uint32_t block, block_addr;
	uint32_t time, i, bytes_read;
	uint8_t *buf;
	int64_t addr = strtoll(line, &endptr, 0);

	if(addr < 0 || endptr == line)
	{
		last_error = S"Invalid address argument";
		return false;
	}
	if(addr > (1 << my_cache->address_bits)-1)
	{
		last_error = S"Address out of range (too many bits)";
		return false;
	}

	block = my_cache->words_block * my_cache->bytes_word;
	sscanf(endptr, " %n", &whitespace);
	line = endptr + whitespace;
	/// If writing, read the address from the input
	/// Otherwise, warn about excess parameters
	if(write)
	{
		if(!*line)
		{
			last_error = S"No data to write";
			return false;
		}
		/// The data could be bigger than 64 bits, so we need
		/// to read it by byte. We also need to start from the end
		endptr = line;
		data_buf[2] = '\0';
		while(*endptr && !isspace(*endptr))
			endptr++;
		check_excess_params(endptr, "write");
		bytes_read = 0;
		while(endptr > line)
		{
			if(endptr - line > 1)
			{
				data_buf[0] = *(endptr - 2);
				data_buf[1] = *(endptr - 1);
				endptr -= 2;
			} else
			{
				data_buf[0] = *(endptr - 1);
				data_buf[1] = '\0';
				endptr -= 1;
			}
			/// Dynamically allocate a read buffer (again, unknown line length)
			if(!read_buf || read_buf_len >= bytes_read)
			{
				read_buf_len = !read_buf_len ? 4 : read_buf_len*2;
				read_buf = U8 realloc(read_buf, read_buf_len);
				if(!read_buf)
				{
					read_buf_len = 0;
					last_error = S"Out of memory (data read buffer)";
					return false;
				}
			}
			read_buf[bytes_read] = strtol(data_buf, &test, 16);
			if(test == data_buf)
			{
				last_error = S"Invalid data";
				return false;
			}
			bytes_read++;
		}
		if(bytes_read > block)
		{
			last_error = S"Data length greater than block size";
			return false;
		}
		if(bytes_read != my_cache->bytes_word)
			printf(WARNING "Unaligned data; %d bytes in a word, %d read\n",
					my_cache->bytes_word, bytes_read);
	} else
	{
		if(*line)
			print_warning("Excess parameters for read request");
	}

	block_offset = addr % block;
	block_addr = addr - block_offset;
	buf = get_tmp_block(my_cache);
	time = my_cache->hit_time;
	set_index = -1;
	hit = true;
	two_blocks = ((block_offset + my_cache->bytes_word) > block);

	/// We need to read first if: we're not writing, the data size
	/// isn't one block, or the address is not block aligned
	if(block_offset || (bytes_read != block) || !write)
	{
		if(!read_write_cache(my_cache, block_addr, buf, &time,
							timestamp, &set_index, &hit, false))
			return false;
		/// If it's a multi-block read, use the set_index from the first one
		if(two_blocks)
		{
			if(!read_write_cache(my_cache, block_addr + block, buf + block,
									&time, timestamp, NULL, &hit, false))
				return false;
			printf(INFO "Multi-block command (address near block end)\n");
		}
	}

	/// If we're writing, we need to modify the block, then write it back
	if(write)
	{
		for(i = 0; i < bytes_read; i++)
			buf[block_offset + i] = read_buf[i];
		/// We don't need to check for a hit; if there was a miss,
		/// it will have already been picked up by the read
		if(!read_write_cache(my_cache, block_addr, buf, &time, timestamp,
							(set_index < 0) ? &set_index : NULL,
							&hit, true))
			return false;
		if(two_blocks && !read_write_cache(my_cache, block_addr + block,
											buf + block, &time, timestamp,
											NULL, &hit, true))
			return false;
	}

	/// Print the output
	printf("%s-ack %d %s %d ", write ? "write" : "read",
			set_index, hit ? "hit" : "miss", time);
	if(!write)
	{
		buf += block_offset - 1;
		for(i = my_cache->bytes_word; i > 0; i--)
			printf("%02X", buf[i]);
	}
	printf("\n");
	return true;
}

/**
 * Performs a read request ('command' signature)
 **/
static bool read_req(cache* my_cache, char* line, uint64_t timestamp)
{
	return read_write_req(my_cache, line, timestamp, false);
}

/**
 * Performs a write request ('command' signature)
 **/
static bool write_req(cache* my_cache, char* line, uint64_t timestamp)
{
	return read_write_req(my_cache, line, timestamp, true);
}

/**
 * Flushes the cache ('command' signature)
 **/
static bool flush_req(cache* my_cache, char* line, uint64_t timestamp)
{
	uint32_t i, j, block = my_cache->bytes_word * my_cache->words_block;
	uint32_t addr, n_items = my_cache->blocks_set * my_cache->sets_cache;
	uint8_t* data = my_cache->cache_space;
	cache_item* md = my_cache->metadata;
	uint32_t time = 0;
	check_excess_params(line, "flush");

	for(i = 0; i < n_items; i++, md++, data += block)
	{
		time += my_cache->hit_time;
		if(md->valid && md->dirty)
		{
			addr = ((md->tag * my_cache->blocks_set) +
					(i / my_cache->sets_cache)) * block;
			if(!ensure_mem_capacity(my_cache, addr + block))
				return false;
			time += my_cache->memory_write_time;
			for(j = 0; j < block; j++)
				my_cache->memory_space[addr + j] = data[j];
			md->dirty = false;
		}
	}

	printf("flush-ack %d\n", time);
	return true;
}

/**
 * Outputs debug information ('command' signature)
 **/
static bool debug_req(cache* my_cache, char* line, uint64_t timestamp)
{
	uint32_t i, j, block = my_cache->bytes_word * my_cache->words_block;
	uint32_t n_items = my_cache->blocks_set * my_cache->sets_cache;
	uint8_t* data = my_cache->cache_space;
	cache_item* md = my_cache->metadata;
	check_excess_params(line, "debug");

	printf("debug-ack-begin\n"
		   "| Index | Valid | Dirty | Tag        | Timestamp  | Data\n"
		   "+-------+-------+-------+------------+------------+------\n");
	for(i = 0; i < n_items; i++, md++)
	{
		printf("| %5d | %5d | %5d | %10d | %10d | ", (i / my_cache->sets_cache),
				md->valid, md->dirty, md->tag, (uint32_t)md->timestamp);
		for(j = 0; j < block; j++, data++)
			printf("%02X%s",*data, ((j + 1) % my_cache->bytes_word) ? "" : " ");
		printf("\n");
	}
	printf("debug-ack-end\n");
	return true;
}

/**
 * No action ('command' signature)
 **/
static bool comment(cache* my_cache, char* line, uint64_t timestamp)
{
	return true;
}

/**
 * The list of possible commands; name and function
 **/
static const
struct { const char* name; command cmd; }
commands[NUM_COMMANDS] =
{
	{ "#", &comment },
	{ "read-req", &read_req },
	{ "write-req", &write_req },
	{ "flush-req", &flush_req },
	{ "debug-req", &debug_req }
};

/**
 * The list of default parameters; name and value
 **/
static const
struct { const char* name; uint32_t value; }
default_values[NUM_PARAMS] =
{
	{ "Address bits", 8 },		/// Address bits
	{ "Bytes per word", 2 },	/// Bytes/word
	{ "Words per block", 2 },	/// Word/block
	{ "Blocks per set", 1 },	/// Blocks/set
	{ "Number of sets", 2 },	/// Sets/cache
	{ "Hit time", 1 },			/// Cache hit time
	{ "Memory read time", 2 },	/// Memory read time
	{ "Memory write time", 2 }	/// Memory write time
};

/**
 * Entry point
 **/
int main(int argc, char* argv[])
{
	cache my_cache;
	int i;
	int tmp;
	uint32_t* start_params = &my_cache.address_bits;
	char buffer[BUF_SIZE], cmd_buf[BUF_SIZE];
	command cmd;
	uint64_t timestamp = 1;

	/// Read in all the command line parameters
	for(i = 0; i < NUM_PARAMS; i++)
	{
		if(i+1 >= argc)
		{
			printf(WARNING "%s unset; assuming %d\n", default_values[i].name,
					default_values[i].value);
			*(start_params + i) = default_values[i].value;
		}
		else
		{
			tmp = strtol(argv[i + 1], NULL, 0);
			if(!tmp || tmp < 0)
			{
				printf(ERROR "%s is invalid; assuming %d\n",
						default_values[i].name, default_values[i].value);
				*(start_params + i) = default_values[i].value;
			}
			else
			{
				*(start_params + i) = tmp;
			}
		}
	}
	if(argc > (NUM_PARAMS + 1))
		print_warning("Excess program parameters");

	/// Perform the commands using stdin
	if(create_cache(&my_cache))
	{
		while(fgets(buffer, BUF_SIZE, stdin))
		{
			if(sscanf(buffer, " %s %n", cmd_buf, &tmp) < 1)
				continue;
			cmd = NULL;
			for(i = 0; i < NUM_COMMANDS; i++)
			{
				if(streq(cmd_buf, commands[i].name))
				{
					cmd = commands[i].cmd;
					break;
				}
			}
			if(!cmd)
				printf(ERROR "Unknown command: %s\n", cmd_buf);
			else if(!cmd(&my_cache, buffer + tmp, timestamp))
				print_error();
			timestamp++;
		}
	}
	print_error();
	return 0;
}
