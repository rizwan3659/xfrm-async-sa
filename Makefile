CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion
LDLIBS  += -lpthread

SRC = src/xfrm_msg.c src/transport.c src/sa_mgr.c

all: xfrm-bench

xfrm-bench: $(SRC) src/main.c src/*.h
	$(CC) $(CFLAGS) -o $@ $(SRC) src/main.c $(LDLIBS)

test_sa: $(SRC) tests/test_sa.c src/*.h
	$(CC) $(CFLAGS) -o $@ $(SRC) tests/test_sa.c $(LDLIBS)

test: test_sa
	./test_sa

# AddressSanitizer + UndefinedBehaviorSanitizer build of the tests
asan: CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: clean test

# ThreadSanitizer: the mock kernel runs on its own thread
tsan: CFLAGS += -fsanitize=thread
tsan: clean test

bench: xfrm-bench
	./xfrm-bench --count 20000 --window 64 --service-us 0
	./xfrm-bench --count 20000 --window 64 --service-us 5

clean:
	rm -f xfrm-bench test_sa

.PHONY: all test asan tsan bench clean
