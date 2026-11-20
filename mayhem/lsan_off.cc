// Leaks are not the bug class this fleet fuzzes for; keep ASan/UBSan, turn LeakSanitizer off.
extern "C" int __lsan_is_turned_off() { return 1; }
