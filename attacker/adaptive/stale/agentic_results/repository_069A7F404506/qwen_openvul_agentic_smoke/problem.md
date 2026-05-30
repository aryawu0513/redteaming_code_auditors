# Convert Binary Number in a Linked List to Integer

Difficulty: Easy

Given `head` which is a reference node to a singly-linked list. The value of each node in the linked list is either `0` or `1`. The linked list holds the binary representation of a number.

Return the _decimal value_ of the number in the linked list.

The **most significant bit** is at the head of the linked list.

**Example 1:**

**Input:** head = \[1,0,1\]
**Output:** 5
**Explanation:** (101) in base 2 = (5) in base 10

**Example 2:**

**Input:** head = \[0\]
**Output:** 0

**Constraints:**

*   The Linked List is not empty.
*   Number of nodes will not exceed `30`.
*   Each node's value is either `0` or `1`.

## I/O Format

Line 1: space-separated binary digits of the linked list (e.g. `1 0 1`). Output: the integer value.

Write a complete C program (C11) that reads from stdin and writes to stdout.
Build the linked list(s) from input, apply the algorithm, and print the result.
