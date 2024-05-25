CC := gcc
COMPILE := $(CC) -c
LINK := $(CC) -lcrypto
SRC_DIR := src/
TEST_DIR := test/
BUILD_DIR := build/
OBJS_DIR := $(BUILD_DIR)objs/
CFLAGS := -I. -I$(SRC_DIR) -Wall -Werror -lcrypto -g

CLIENT_SRCS := $(SRC_DIR)tls_impl.c \
  $(SRC_DIR)simple_tls.c \
  $(SRC_DIR)tls_connection.c
CLIENT_OBJS := $(CLIENT_SRCS:$(SRC_DIR)%.c=$(OBJS_DIR)%.o)


SERVER_SRCS := $(SRC_DIR)tls_server.c
SERVER_OBJS := $(SERVER_SRCS:$(SRC_DIR)%.c=$(OBJS_DIR)%.o)

SRCS := $(wildcard $(SRC_DIR)*.c)
OBJS := $(SRCS:$(SRC_DIR)%.c=$(OBJS_DIR)%.o)
DEPENDS := $(OBJS:%.o=%.d)


TEST_BUILD_DIR := $(BUILD_DIR)tests/
TEST_OBJS_DIR := $(TEST_BUILD_DIR)objs/

TESTS := $(wildcard $(TEST_DIR)*.c)
TEST_OBJS := $(TESTS:$(TEST_DIR)%.c=$(TEST_OBJS_DIR)%.o)
TEST_DEPENDS := $(TEST_OBJS:%.o=%.d)

UNITY_TESTS := $(wildcard $(TEST_DIR)test_*.c)
UNITY_TESTS_OBJS := $(UNITY_TESTS:$(TEST_DIR)%.c=$(TEST_OBJS_DIR)%.o)
UNITY_DIR := unity/src/
UNITY_FIXTURE_DIR := unity/extras/fixture/src/
UNITY_MEMORY_DIR := unity/extras/memory/src/

UNITY_OBJS := $(TEST_OBJS_DIR)unity.o \
  $(TEST_OBJS_DIR)unity_fixture.o \
  $(TEST_OBJS_DIR)unity_memory.o

CFLAGS_TESTS := -I$(UNITY_DIR) -I$(UNITY_FIXTURE_DIR) -I$(UNITY_MEMORY_DIR)



.PHONY: all
all: $(BUILD_DIR)simple_tls $(BUILD_DIR)tls_server

$(BUILD_DIR)simple_tls: $(CLIENT_OBJS) | build_dir
	$(LINK) -o $@ $^

$(BUILD_DIR)tls_server: $(SERVER_SRCS) | build_dir
	$(CC) $(CFLAGS) -lssl -o $@ $^


$(OBJS_DIR)%.o: $(SRC_DIR)%.c | build_dir
	$(CC) $(CFLAGS) -MM -MP -MT '$@' -o $(patsubst %.o,%.d,$@) $<
	$(COMPILE) $(CFLAGS) -c -o $@ $<

.PHONY: check
check: $(TEST_BUILD_DIR)run_tests
	@./$<

.PHONY: check-valgrind
check-valgrind: $(TEST_BUILD_DIR)run_tests
	@valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes -s ./$<


$(TEST_BUILD_DIR)run_tests: $(UNITY_OBJS) \
  $(UNITY_TESTS_OBJS) \
  $(OBJS_DIR)tls_connection.o \
  $(OBJS_DIR)tls_impl.o \
  $(TEST_OBJS_DIR)run_tests.o | build_dir
	$(LINK) -o $@ $^




$(TEST_OBJS_DIR)%.o: $(TEST_DIR)%.c | build_dir
	$(CC) $(CFLAGS) $(CFLAGS_TESTS) -MM -MP -MT '$@' -o $(patsubst %.o,%.d,$@) $<
	$(COMPILE) $(CFLAGS) $(CFLAGS_TESTS) -o $@ $<

$(TEST_OBJS_DIR)%.o: $(UNITY_DIR)%.c | build_dir
	$(COMPILE) $(CFLAGS) $(CFLAGS_TESTS) -o $@ $<

$(TEST_OBJS_DIR)%.o: $(UNITY_FIXTURE_DIR)%.c | build_dir
	$(COMPILE) $(CFLAGS) $(CFLAGS_TESTS) -o $@ $<

$(TEST_OBJS_DIR)%.o: $(UNITY_MEMORY_DIR)%.c | build_dir
	$(COMPILE) $(CFLAGS) $(CFLAGS_TESTS) -o $@ $<


.PHONY: build_dir
build_dir: $(BUILD_DIR) $(OBJS_DIR) $(TEST_DIR) $(TEST_OBJS_DIR)

$(BUILD_DIR):
	mkdir -p $@

$(OBJS_DIR):
	mkdir -p $@

$(TEST_BUILD_DIR):
	mkdir -p $@

$(TEST_OBJS_DIR):
	mkdir -p $@


-include $(DEPENDS)
-include $(TEST_DEPENDS)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: format
format:
	indent -kr $(SRC_DIR)*.c $(SRC_DIR)*.h $(TEST_DIR)*.c $(TEST_DIR)*.h
	rm -rf $(SRC_DIR)*~ $(TEST_DIR)*~

.PRECIOUS: %.o
.PRECIOUS: %.d
