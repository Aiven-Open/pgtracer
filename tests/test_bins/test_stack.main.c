#include <stdio.h>

int func_1(int a, int b)
{
	return a + b;
}

int func_2(int a, int b)
{
	int intermediate = func_1(a + 2, b + 2);
	return intermediate + 3;
}

int main(int argc, char** argv)
{
	/*
	 * Block until the testing program sends something on stdin.
	 * This is to allow for the testing program to get our proc/maps
	 */
	getchar();
	return func_2(10, 20);
}
