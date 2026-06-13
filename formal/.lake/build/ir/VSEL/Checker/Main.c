// Lean compiler output
// Module: VSEL.Checker.Main
// Imports: Init VSEL.Checker.Certificate
#include <lean/lean.h>
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-label"
#elif defined(__GNUC__) && !defined(__CLANG__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-label"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif
#ifdef __cplusplus
extern "C" {
#endif
static lean_object* l_VSEL_Checker_renderError___closed__7;
LEAN_EXPORT lean_object* _lean_main(lean_object*, lean_object*);
static lean_object* l_VSEL_Checker_runMain___closed__1;
static lean_object* l_VSEL_Checker_renderError___closed__4;
static lean_object* l_VSEL_Checker_renderError___closed__1;
static lean_object* l_VSEL_Checker_renderError___closed__6;
lean_object* l_IO_println___at_Lean_instEval___spec__1(lean_object*, lean_object*);
static lean_object* l_VSEL_Checker_renderError___closed__3;
LEAN_EXPORT lean_object* l_VSEL_Checker_runMain(lean_object*, lean_object*);
static lean_object* l_VSEL_Checker_renderError___closed__8;
LEAN_EXPORT lean_object* l_VSEL_Checker_runMain___boxed(lean_object*, lean_object*);
static lean_object* l_VSEL_Checker_runMain___closed__2;
static lean_object* l_VSEL_Checker_renderError___closed__2;
lean_object* l_VSEL_Checker_checkCertificateText(lean_object*);
LEAN_EXPORT lean_object* l_VSEL_Checker_renderError___boxed(lean_object*);
lean_object* l_IO_FS_readFile(lean_object*, lean_object*);
static lean_object* l_VSEL_Checker_runMain___closed__3;
LEAN_EXPORT lean_object* l_VSEL_Checker_renderError(lean_object*);
lean_object* lean_string_append(lean_object*, lean_object*);
static lean_object* l_VSEL_Checker_runMain___closed__4;
static lean_object* l_VSEL_Checker_renderError___closed__5;
static lean_object* _init_l_VSEL_Checker_renderError___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_from_bytes("empty certificate", 17);
return x_1;
}
}
static lean_object* _init_l_VSEL_Checker_renderError___closed__2() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_from_bytes("invalid certificate header", 26);
return x_1;
}
}
static lean_object* _init_l_VSEL_Checker_renderError___closed__3() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_from_bytes("malformed certificate line: ", 28);
return x_1;
}
}
static lean_object* _init_l_VSEL_Checker_renderError___closed__4() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_from_bytes("duplicate certificate field: ", 29);
return x_1;
}
}
static lean_object* _init_l_VSEL_Checker_renderError___closed__5() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_from_bytes("missing certificate field: ", 27);
return x_1;
}
}
static lean_object* _init_l_VSEL_Checker_renderError___closed__6() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_from_bytes("invalid certificate field ", 26);
return x_1;
}
}
static lean_object* _init_l_VSEL_Checker_renderError___closed__7() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_from_bytes(": ", 2);
return x_1;
}
}
static lean_object* _init_l_VSEL_Checker_renderError___closed__8() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_from_bytes("missing semantic obligation: ", 29);
return x_1;
}
}
LEAN_EXPORT lean_object* l_VSEL_Checker_renderError(lean_object* x_1) {
_start:
{
switch (lean_obj_tag(x_1)) {
case 0:
{
lean_object* x_2; 
x_2 = l_VSEL_Checker_renderError___closed__1;
return x_2;
}
case 1:
{
lean_object* x_3; 
x_3 = l_VSEL_Checker_renderError___closed__2;
return x_3;
}
case 2:
{
lean_object* x_4; lean_object* x_5; lean_object* x_6; 
x_4 = lean_ctor_get(x_1, 0);
x_5 = l_VSEL_Checker_renderError___closed__3;
x_6 = lean_string_append(x_5, x_4);
return x_6;
}
case 3:
{
lean_object* x_7; lean_object* x_8; lean_object* x_9; 
x_7 = lean_ctor_get(x_1, 0);
x_8 = l_VSEL_Checker_renderError___closed__4;
x_9 = lean_string_append(x_8, x_7);
return x_9;
}
case 4:
{
lean_object* x_10; lean_object* x_11; lean_object* x_12; 
x_10 = lean_ctor_get(x_1, 0);
x_11 = l_VSEL_Checker_renderError___closed__5;
x_12 = lean_string_append(x_11, x_10);
return x_12;
}
case 5:
{
lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; lean_object* x_17; lean_object* x_18; lean_object* x_19; 
x_13 = lean_ctor_get(x_1, 0);
x_14 = lean_ctor_get(x_1, 1);
x_15 = l_VSEL_Checker_renderError___closed__6;
x_16 = lean_string_append(x_15, x_13);
x_17 = l_VSEL_Checker_renderError___closed__7;
x_18 = lean_string_append(x_16, x_17);
x_19 = lean_string_append(x_18, x_14);
return x_19;
}
default: 
{
lean_object* x_20; lean_object* x_21; lean_object* x_22; 
x_20 = lean_ctor_get(x_1, 0);
x_21 = l_VSEL_Checker_renderError___closed__8;
x_22 = lean_string_append(x_21, x_20);
return x_22;
}
}
}
}
LEAN_EXPORT lean_object* l_VSEL_Checker_renderError___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_VSEL_Checker_renderError(x_1);
lean_dec(x_1);
return x_2;
}
}
static lean_object* _init_l_VSEL_Checker_runMain___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_from_bytes("usage: vselCheck <semantic-certificate-file>", 44);
return x_1;
}
}
static lean_object* _init_l_VSEL_Checker_runMain___closed__2() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = l_VSEL_Checker_runMain___closed__1;
x_2 = lean_alloc_ctor(18, 1, 0);
lean_ctor_set(x_2, 0, x_1);
return x_2;
}
}
static lean_object* _init_l_VSEL_Checker_runMain___closed__3() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_from_bytes("VSEL semantic certificate rejected: ", 36);
return x_1;
}
}
static lean_object* _init_l_VSEL_Checker_runMain___closed__4() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_from_bytes("VSEL semantic certificate accepted", 34);
return x_1;
}
}
LEAN_EXPORT lean_object* l_VSEL_Checker_runMain(lean_object* x_1, lean_object* x_2) {
_start:
{
if (lean_obj_tag(x_1) == 0)
{
lean_object* x_3; lean_object* x_4; 
x_3 = l_VSEL_Checker_runMain___closed__2;
x_4 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_4, 0, x_3);
lean_ctor_set(x_4, 1, x_2);
return x_4;
}
else
{
lean_object* x_5; 
x_5 = lean_ctor_get(x_1, 1);
if (lean_obj_tag(x_5) == 0)
{
lean_object* x_6; lean_object* x_7; 
x_6 = lean_ctor_get(x_1, 0);
x_7 = l_IO_FS_readFile(x_6, x_2);
if (lean_obj_tag(x_7) == 0)
{
uint8_t x_8; 
x_8 = !lean_is_exclusive(x_7);
if (x_8 == 0)
{
lean_object* x_9; lean_object* x_10; lean_object* x_11; 
x_9 = lean_ctor_get(x_7, 0);
x_10 = lean_ctor_get(x_7, 1);
x_11 = l_VSEL_Checker_checkCertificateText(x_9);
if (lean_obj_tag(x_11) == 0)
{
lean_object* x_12; lean_object* x_13; lean_object* x_14; lean_object* x_15; lean_object* x_16; 
x_12 = lean_ctor_get(x_11, 0);
lean_inc(x_12);
lean_dec(x_11);
x_13 = l_VSEL_Checker_renderError(x_12);
lean_dec(x_12);
x_14 = l_VSEL_Checker_runMain___closed__3;
x_15 = lean_string_append(x_14, x_13);
lean_dec(x_13);
x_16 = lean_alloc_ctor(18, 1, 0);
lean_ctor_set(x_16, 0, x_15);
lean_ctor_set_tag(x_7, 1);
lean_ctor_set(x_7, 0, x_16);
return x_7;
}
else
{
lean_object* x_17; lean_object* x_18; 
lean_dec(x_11);
lean_free_object(x_7);
x_17 = l_VSEL_Checker_runMain___closed__4;
x_18 = l_IO_println___at_Lean_instEval___spec__1(x_17, x_10);
return x_18;
}
}
else
{
lean_object* x_19; lean_object* x_20; lean_object* x_21; 
x_19 = lean_ctor_get(x_7, 0);
x_20 = lean_ctor_get(x_7, 1);
lean_inc(x_20);
lean_inc(x_19);
lean_dec(x_7);
x_21 = l_VSEL_Checker_checkCertificateText(x_19);
if (lean_obj_tag(x_21) == 0)
{
lean_object* x_22; lean_object* x_23; lean_object* x_24; lean_object* x_25; lean_object* x_26; lean_object* x_27; 
x_22 = lean_ctor_get(x_21, 0);
lean_inc(x_22);
lean_dec(x_21);
x_23 = l_VSEL_Checker_renderError(x_22);
lean_dec(x_22);
x_24 = l_VSEL_Checker_runMain___closed__3;
x_25 = lean_string_append(x_24, x_23);
lean_dec(x_23);
x_26 = lean_alloc_ctor(18, 1, 0);
lean_ctor_set(x_26, 0, x_25);
x_27 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_27, 0, x_26);
lean_ctor_set(x_27, 1, x_20);
return x_27;
}
else
{
lean_object* x_28; lean_object* x_29; 
lean_dec(x_21);
x_28 = l_VSEL_Checker_runMain___closed__4;
x_29 = l_IO_println___at_Lean_instEval___spec__1(x_28, x_20);
return x_29;
}
}
}
else
{
uint8_t x_30; 
x_30 = !lean_is_exclusive(x_7);
if (x_30 == 0)
{
return x_7;
}
else
{
lean_object* x_31; lean_object* x_32; lean_object* x_33; 
x_31 = lean_ctor_get(x_7, 0);
x_32 = lean_ctor_get(x_7, 1);
lean_inc(x_32);
lean_inc(x_31);
lean_dec(x_7);
x_33 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_33, 0, x_31);
lean_ctor_set(x_33, 1, x_32);
return x_33;
}
}
}
else
{
lean_object* x_34; lean_object* x_35; 
x_34 = l_VSEL_Checker_runMain___closed__2;
x_35 = lean_alloc_ctor(1, 2, 0);
lean_ctor_set(x_35, 0, x_34);
lean_ctor_set(x_35, 1, x_2);
return x_35;
}
}
}
}
LEAN_EXPORT lean_object* l_VSEL_Checker_runMain___boxed(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_VSEL_Checker_runMain(x_1, x_2);
lean_dec(x_1);
return x_3;
}
}
LEAN_EXPORT lean_object* _lean_main(lean_object* x_1, lean_object* x_2) {
_start:
{
lean_object* x_3; 
x_3 = l_VSEL_Checker_runMain(x_1, x_2);
lean_dec(x_1);
return x_3;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_VSEL_Checker_Certificate(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_VSEL_Checker_Main(uint8_t builtin, lean_object* w) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_VSEL_Checker_Certificate(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
l_VSEL_Checker_renderError___closed__1 = _init_l_VSEL_Checker_renderError___closed__1();
lean_mark_persistent(l_VSEL_Checker_renderError___closed__1);
l_VSEL_Checker_renderError___closed__2 = _init_l_VSEL_Checker_renderError___closed__2();
lean_mark_persistent(l_VSEL_Checker_renderError___closed__2);
l_VSEL_Checker_renderError___closed__3 = _init_l_VSEL_Checker_renderError___closed__3();
lean_mark_persistent(l_VSEL_Checker_renderError___closed__3);
l_VSEL_Checker_renderError___closed__4 = _init_l_VSEL_Checker_renderError___closed__4();
lean_mark_persistent(l_VSEL_Checker_renderError___closed__4);
l_VSEL_Checker_renderError___closed__5 = _init_l_VSEL_Checker_renderError___closed__5();
lean_mark_persistent(l_VSEL_Checker_renderError___closed__5);
l_VSEL_Checker_renderError___closed__6 = _init_l_VSEL_Checker_renderError___closed__6();
lean_mark_persistent(l_VSEL_Checker_renderError___closed__6);
l_VSEL_Checker_renderError___closed__7 = _init_l_VSEL_Checker_renderError___closed__7();
lean_mark_persistent(l_VSEL_Checker_renderError___closed__7);
l_VSEL_Checker_renderError___closed__8 = _init_l_VSEL_Checker_renderError___closed__8();
lean_mark_persistent(l_VSEL_Checker_renderError___closed__8);
l_VSEL_Checker_runMain___closed__1 = _init_l_VSEL_Checker_runMain___closed__1();
lean_mark_persistent(l_VSEL_Checker_runMain___closed__1);
l_VSEL_Checker_runMain___closed__2 = _init_l_VSEL_Checker_runMain___closed__2();
lean_mark_persistent(l_VSEL_Checker_runMain___closed__2);
l_VSEL_Checker_runMain___closed__3 = _init_l_VSEL_Checker_runMain___closed__3();
lean_mark_persistent(l_VSEL_Checker_runMain___closed__3);
l_VSEL_Checker_runMain___closed__4 = _init_l_VSEL_Checker_runMain___closed__4();
lean_mark_persistent(l_VSEL_Checker_runMain___closed__4);
return lean_io_result_mk_ok(lean_box(0));
}
void lean_initialize_runtime_module();

  #if defined(WIN32) || defined(_WIN32)
  #include <windows.h>
  #endif

  int main(int argc, char ** argv) {
  #if defined(WIN32) || defined(_WIN32)
  SetErrorMode(SEM_FAILCRITICALERRORS);
  #endif
  lean_object* in; lean_object* res;
lean_initialize_runtime_module();
lean_set_panic_messages(false);
res = initialize_VSEL_Checker_Main(1 /* builtin */, lean_io_mk_world());
lean_set_panic_messages(true);
lean_io_mark_end_initialization();
if (lean_io_result_is_ok(res)) {
lean_dec_ref(res);
lean_init_task_manager();
in = lean_box(0);
int i = argc;
while (i > 1) {
 lean_object* n;
 i--;
 n = lean_alloc_ctor(1,2,0); lean_ctor_set(n, 0, lean_mk_string(argv[i])); lean_ctor_set(n, 1, in);
 in = n;
}
res = _lean_main(in, lean_io_mk_world());
}
lean_finalize_task_manager();
if (lean_io_result_is_ok(res)) {
  int ret = 0;
  lean_dec_ref(res);
  return ret;
} else {
  lean_io_result_show_error(res);
  lean_dec_ref(res);
  return 1;
}
}
#ifdef __cplusplus
}
#endif
