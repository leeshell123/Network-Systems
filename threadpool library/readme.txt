this is a simple threadpool library implemented by myself.

It uses pthread library.

This library provide several functions:

ThreadPool(size t threadCount)
¡«ThreadPool( )
int dispatch_thread(void dispatch_function(void*), void *arg)
bool thread avail( )


The first function is a constructor function that creates a ThreadPool object consisting of a
set of threadCount threads. The second function is the destructor function.
The third function dispatches a thread from the thread pool to execute the dispatch function().
After completing the execution of the dispatch function(), the thread returns to the thread
pool. The dispatch function() function has one parameter, arg. Finally, the fourth function
returns true if a thread is currently available in the thread pool, and false otherwise.
