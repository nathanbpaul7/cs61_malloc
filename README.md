CS 61 Problem Set 1
===================

Debugging Dynamic Memory Allocator completed as part of problem set 1 for CS-61 coursework that I'm auditing independently.

Key Takeaways from Building a Memory Allocator:

Pointer arithmetic is a careful art! In order to traverse data structures successfully, I needed to be mindful to cast pointers to a char* before working with size_t integers to increment an iterator or check for allotted blocks/freed blocks.

C++ data structures are handy! Instead of building a custom linked list with my own node structure, I used std::map and std::vector to create key value lists I could traverse and iterate over easily. If i had more custom needs or specific memory / speed limitations, perhaps my use of those structures would be less wise, and I’d need to cook up my own better linked list or hash/trie.

It seems clear that these tests for driving development are incredibly helpful, but they’re limited in that they only test for bugs that are predictable, and as such can't be relied on solely to esnure a stable and bug-proof end product.

