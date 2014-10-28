
#include <vector>
#include <queue>


using namespace std;

typedef struct
{
	void (*dispatch_function)(void*);
	void* arg;
}work_t;



class ThreadPool
{
public:
  ThreadPool(size_t threadCount);
  ~ThreadPool();
  int dispatch_thread(void dispatch_function(void*), void *arg);
  bool thread_avail();
  void* execute_thread();
private:
  int availableThreads;
  volatile int pool_state;
  int pool_size;
  //void* thread_function(void * arg);
  queue<work_t> workQueue;
  pthread_mutex_t workQueueLock;
  pthread_mutex_t availableThreadLock;
  
  sem_t taskno;
  std::vector<pthread_t> m_threads;
  
};

extern "C"
void* start_thread(void* arg)
{
  ThreadPool* tp = (ThreadPool*) arg;
  tp->execute_thread();
  return NULL;
}

ThreadPool::ThreadPool(size_t threadCount)
{
	pthread_mutex_init(&workQueueLock, NULL);
	pthread_mutex_init(&availableThreadLock, NULL);
	pool_size = threadCount;
	availableThreads = threadCount;
	sem_init(&taskno, 0, 0);
	int ret = -1;
	  for (int i = 0; i < pool_size; i++) {
		pthread_t tid;
	    ret = pthread_create(&tid, NULL, start_thread, (void*) this);
	    if (ret != 0) {
	      cerr << "pthread_create() failed: " << ret << endl;
	    }
	    m_threads.push_back(tid);
	    //pthread_join(tid, NULL);  //do we need to wait till the thread is finished?
	  }
	  cout << pool_size << " threads created by the thread pool" << endl;	
}

ThreadPool::~ThreadPool(){
	while(!workQueue.empty()){}
	pthread_mutex_destroy(&workQueueLock);
	pthread_mutex_destroy(&availableThreadLock);
	sem_destroy(&taskno);
}

int ThreadPool::dispatch_thread(void dispatch_function(void*), void *arg)
{
	work_t newwork;
	newwork.dispatch_function = dispatch_function;
	newwork.arg = arg;
	
	pthread_mutex_lock(&workQueueLock);	
	workQueue.push(newwork);
	sem_post(&taskno);
	pthread_mutex_unlock(&workQueueLock);
}

void* ThreadPool::execute_thread(){
	while(1){
		sem_wait(&taskno);
		pthread_mutex_lock(&availableThreadLock);	
		availableThreads--;
		pthread_mutex_unlock(&availableThreadLock);
		
		
		pthread_mutex_lock(&workQueueLock);	
		work_t newwork = workQueue.front();
		workQueue.pop();
		pthread_mutex_unlock(&workQueueLock);
		newwork.dispatch_function(newwork.arg);	
		
		pthread_mutex_lock(&availableThreadLock);	
		availableThreads++;
		pthread_mutex_unlock(&availableThreadLock);
	}	
}

bool ThreadPool::thread_avail(){
	return (availableThreads > 0);
}
