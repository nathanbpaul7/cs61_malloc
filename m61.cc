#include "m61.hh"
#include <cstdlib>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <iostream>
#include <sys/mman.h>
#include <map>

#define CANARY_SIZE 8               // Guard size (could be adjusted)
#define CANARY_VALUE 0xBEEFDAD7      // Guard value (could be adjusted)
struct m61_memory_buffer {
    char* buffer;
    size_t pos = 0;
    size_t size = 8 << 20; /* 8 MiB */

    m61_memory_buffer();
    ~m61_memory_buffer();
};

static m61_memory_buffer default_buffer;

static m61_statistics gstats = {
    .nactive = 0,
    .active_size = 0,
    .ntotal = 0,
    .total_size = 0,
    .nfail = 0,
    .fail_size = 0,
    .heap_min = UINTPTR_MAX,
    .heap_max = (uintptr_t) default_buffer.buffer[0],
    .buffer_end = (uintptr_t) default_buffer.buffer + default_buffer.size,
};


m61_memory_buffer::m61_memory_buffer() {
    void* buf = mmap(nullptr,    // Place the buffer at a random address
        this->size,              // Buffer should be 8 MiB big
        PROT_WRITE,              // We want to read and write the buffer
        MAP_ANON | MAP_PRIVATE, -1, 0);
                                 // We want memory freshly allocated by the OS
    assert(buf != MAP_FAILED);
    this->buffer = (char*) buf;
}

m61_memory_buffer::~m61_memory_buffer() {
    munmap(this->buffer, this->size);
}
struct AllocationInfo {
    size_t tot_size;
    size_t size;
    const char* file;
    int line;
};
static std::map<void*, AllocationInfo> active_sizes;
static std::map<void*, size_t> freed_blocks;

void coalesce(void* current_ptr, size_t current_size) {
    void* next_ptr = static_cast<char*>(current_ptr) + current_size;
    void* buffer_end = static_cast<char*>(default_buffer.buffer) + default_buffer.size;
    void* buffer_pos = static_cast<char*>(default_buffer.buffer) + default_buffer.pos;

    // Keep merging while adjacent blocks exist
    while (true) {
        auto it = freed_blocks.find(next_ptr);
        if (it != freed_blocks.end()) {
            // Next block exists, retrieve its size
            size_t next_size = it->second;

            // Merge the current block with the next block
            current_size += next_size;

            // Remove the next block from the freed_blocks
            freed_blocks.erase(it);

            // Update next_ptr for the next iteration
            next_ptr = static_cast<char*>(current_ptr) + current_size;
            // check if there is an untouched block on the heap buffer next door we can merge with
        
        } else if (next_ptr == buffer_pos && next_ptr < buffer_end) {
            // Next block does not exist, but there is an untouched block on the heap buffer next door, lets add it
            size_t next_size = (uintptr_t) buffer_end - (uintptr_t) buffer_pos;
            current_size += next_size;
            break;
        }
         else {
            // No more adjacent blocks to merge
            break;
        }
    }

    // add the merged block back to freed_blocks
    freed_blocks[current_ptr] = current_size; 
}

// function for finding free blcoks from the freed_blocks map
static void* m61_find_free_space(size_t sz) {
    // do we have a freed allocation that will work?
    for (auto it = freed_blocks.begin(); it != freed_blocks.end(); ) {
            void* ptr = it->first;           // Pointer to the freed memory block
            size_t block_size = it->second;  // Size of the freed block

            // Exact match of block size
            if (block_size == sz) {
                freed_blocks.erase(it); // Remove from freed_blocks
                return ptr; // Return the exact match
            } 
            else if (block_size > sz) { // Block size is larger than requested size
                size_t size_difference = block_size - sz;
                void* new_ptr = static_cast<char*>(ptr) + sz; // Pointer arithmetic

                // Add the new freed block
                freed_blocks[new_ptr] = size_difference; 
                freed_blocks.erase(it); // Remove the original block
                return ptr; // Return the original pointer
            }
            else { // Block size is smaller than requested size, check for adjacent blocks to coalesce
                coalesce(ptr, block_size);
                if (freed_blocks[ptr] == sz) {
                    freed_blocks.erase(it);
                    return ptr;
                } 
                else if (freed_blocks[ptr] > sz) {
                    size_t size_difference = freed_blocks[ptr] - sz;
                    void* new_ptr = static_cast<char*>(ptr) + sz;
                    freed_blocks[new_ptr] = size_difference;
                    freed_blocks.erase(it);
                    return ptr;
                }
            }
             ++it; // Move to the next block
        }
     // No suitable block found
    return nullptr;
    
}

/// m61_malloc(sz, file, line)
///    Returns a pointer to `sz` bytes of freshly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then m61_malloc may
///    return either `nullptr` or a pointer to a unique allocation.
///    The allocation request was made at source code location `file`:`line`.


void* m61_malloc(size_t sz, const char* file, int line) {

    (void) file, (void) line;   // avoid uninitialized variable warnings
    
    if (sz == 0 || sz > SIZE_MAX - CANARY_SIZE) {
        gstats.fail_size += sz; // update fail size
        ++gstats.nfail;
        return nullptr; // Handle zero-size allocation
    }
    // adjust size to include a canary value at begining and end of allocation
    size_t total_sz = sz + CANARY_SIZE;


    if (default_buffer.pos + total_sz > default_buffer.size || total_sz > default_buffer.size) {
        // Not enough space left in default buffer for allocation
        // let's look for some freed blocks that could help!
        void* ptr = m61_find_free_space(total_sz);
        if (!ptr) {
             gstats.fail_size += sz; // update fail size
            ++gstats.nfail;
            return nullptr;
        }
        else {
            gstats.heap_min = std::min(gstats.heap_min, (uintptr_t) ptr); // checks heap_min address and updates if necessary due to ptr being new minimum
            ++gstats.nactive;
            ++gstats.ntotal;
            active_sizes[ptr] = {total_sz, sz, file, line}; // add the new allocation to active_sizes
            gstats.active_size += sz; // update active size
            gstats.heap_max = std::max(gstats.heap_max, (uintptr_t) ptr + total_sz);  //  update heap_max
            gstats.total_size += sz;  // update total size
            // set canary value at beginning and end of newly allocated block  
            *((uint64_t*)((char*)ptr + sz)) = CANARY_VALUE;
            return ptr;
        }
    }


    // Otherwise there is enough space; claim the next `total_sz` bytes
    void* ptr = &default_buffer.buffer[default_buffer.pos];
    gstats.heap_min = std::min(gstats.heap_min, (uintptr_t) ptr); // checks heap_min address and updates if necessary due to ptr being new minimum
    ++gstats.nactive;
    ++gstats.ntotal;
    active_sizes[ptr] = {total_sz, sz, file, line};
    gstats.active_size += sz;
    default_buffer.pos += total_sz;
    gstats.heap_max = std::max(gstats.heap_max, (uintptr_t) ptr + total_sz);
    gstats.total_size += sz; 
    *((uint64_t*)((char*)ptr + sz)) = CANARY_VALUE;
    return ptr;
  
}


/// m61_free(ptr, file, line)
///    Frees the memory allocation pointed to by `ptr`. If `ptr == nullptr`,
///    does nothing. Otherwise, `ptr` must point to a currently active
///    allocation returned by `m61_malloc`. The free was called at location
///    `file`:`line`.

void m61_free(void* ptr, const char* file, int line) {
    // avoid uninitialized variable warnings
    (void) ptr, (void) file, (void) line;
        // Get the original allocated pointer, including guards

    if (!ptr) 
        // do nothing in c++
        return;
    if (freed_blocks.find(ptr) != freed_blocks.end()) {
        // ptr is already a freed block, print error message and abort
        std::cerr << "MEMORY BUG: " << file << ":" << line 
                  << ": invalid free of pointer " << ptr 
                  << ", double free\n";
        std::abort();
    }
    if (ptr < (void*) gstats.heap_min || ptr >= (void*) gstats.heap_max) {
        // ptr is not a valid heap address, print error message and abort
        std::cerr << "MEMORY BUG: " << file << ":" << line 
                  << ": invalid free of pointer " << ptr 
                  << ", not in heap\n";
        std::abort();
    }
     if (active_sizes.find(ptr) == active_sizes.end()) { 
        // ptr is not an active allocation, lets check if it's inside an active block
        for (auto it = active_sizes.begin(); it != active_sizes.end(); ++it) {
            void* active_ptr = it->first;
            size_t active_size = it->second.tot_size;
            if (ptr > active_ptr && ptr < (void*)((char*)active_ptr + active_size)) {
                // ptr is inside an active block, print error message and abort
                std::cerr << "MEMORY BUG: " << file << ":" << line 
                          << ": invalid free of pointer " << ptr 
                          << ", not allocated\n"
                          << "  " << it->second.file << ":" << it->second.line << ": " 
                          << ptr << " is " << (uintptr_t)ptr - (uintptr_t)active_ptr << " bytes inside a " 
                          << it->second.size << " byte region allocated here\n";
                          
                std::abort();
            }
            }
        
         std::cerr << "MEMORY BUG: " << file << ":" << line 
                  << ": invalid free of pointer " << ptr 
                  << ", not allocated\n";
        std::abort();
    }

    
    // Otherwise, ptr is an active allocation, let's find out how big the block is and free it
    size_t sz = active_sizes[ptr].tot_size;
    // Check if the canary vlaue was overwritten (after the block)
    if (*(uint64_t*) ((char*)ptr + sz - CANARY_SIZE) != CANARY_VALUE) {
        std::cerr << "MEMORY BUG: " << file << ":" << line
                  << ": detected wild write during free of pointer " << ptr << "\n";
        std::abort();
    }
    freed_blocks[ptr] = sz;
    active_sizes.erase(ptr);
    gstats.active_size -= sz - CANARY_SIZE; // update active size
    --gstats.nactive; // update active count
}


/// m61_calloc(count, sz, file, line)
///    Returns a pointer a fresh dynamic memory allocation big enough to
///    hold an array of `count` elements of `sz` bytes each. Returned
///    memory is initialized to zero. The allocation request was at
///    location `file`:`line`. Returns `nullptr` if out of memory; may
///    also return `nullptr` if `count == 0` or `size == 0`.

void* m61_calloc(size_t count, size_t sz, const char* file, int line) {
    
    if (count == 0 || sz == 0) {
        return nullptr;
    }
    // Check for overflow before multiplication
    if (count > SIZE_MAX / sz) {
        gstats.fail_size += count * sz;
        ++gstats.nfail;
        return nullptr;
    }

    void* ptr = m61_malloc(count * sz, file, line);
    if (ptr) {
        memset(ptr, 0, count * sz);
    }
    return ptr;
}


/// m61_get_statistics()
///    Return the current memory statistics.

m61_statistics m61_get_statistics() {
    return gstats;
}


/// m61_print_statistics()
///    Prints the current memory statistics.

void m61_print_statistics() {
    m61_statistics stats = m61_get_statistics();
    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// m61_print_leak_report()
///    Prints a report of all currently-active allocated blocks of dynamic
///    memory.

void m61_print_leak_report() {

    // Your code here.
    for (auto it = active_sizes.begin(); it != active_sizes.end(); ++it) {
        void* ptr = it->first;
        size_t size = it->second.size;
        printf("LEAK CHECK: %s:%d: allocated object %p with size %zu\n",it->second.file, it->second.line, ptr, size);
    }
}

