// Lean compiler output
// Module: VSEL.Refinement.FormalToSIR
// Imports: Init VSEL.Foundations.State VSEL.Foundations.Input VSEL.Foundations.Transition VSEL.Foundations.Invariants
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
LEAN_EXPORT lean_object* l_VSEL_Refinement_instInhabitedInput;
static lean_object* l_VSEL_Refinement_instInhabitedInput___closed__3;
static lean_object* l_VSEL_Refinement_instInhabitedInput___closed__4;
LEAN_EXPORT lean_object* l_VSEL_Refinement_SIR__to__Formal__State___boxed(lean_object*);
static lean_object* l_VSEL_Refinement_SIR__to__Formal__State___closed__7;
static lean_object* l_VSEL_Refinement_SIR__to__Formal__State___closed__9;
static lean_object* l_VSEL_Refinement_instInhabitedInput___closed__5;
static lean_object* l_VSEL_Refinement_SIR__to__Formal__State___closed__1;
LEAN_EXPORT lean_object* l_VSEL_Refinement_SIR__to__Formal__Input(lean_object*);
lean_object* l_List_replicateTR___rarg(lean_object*, lean_object*);
static lean_object* l_VSEL_Refinement_SIR__to__Formal__State___closed__5;
static lean_object* l_VSEL_Refinement_SIR__to__Formal__State___closed__3;
static lean_object* l_VSEL_Refinement_SIR__to__Formal__State___closed__8;
LEAN_EXPORT lean_object* l_VSEL_Refinement_SIR__to__Formal__Input___boxed(lean_object*);
static lean_object* l_VSEL_Refinement_SIR__to__Formal__State___closed__4;
static lean_object* l_VSEL_Refinement_SIR__to__Formal__State___closed__10;
static lean_object* l_VSEL_Refinement_SIR__to__Formal__State___closed__11;
static lean_object* l_VSEL_Refinement_instInhabitedInput___closed__2;
static lean_object* l_VSEL_Refinement_SIR__to__Formal__State___closed__2;
static lean_object* l_VSEL_Refinement_SIR__to__Formal__State___closed__6;
LEAN_EXPORT lean_object* l_VSEL_Refinement_SIR__to__Formal__State(lean_object*);
static lean_object* l_VSEL_Refinement_instInhabitedInput___closed__6;
static lean_object* l_VSEL_Refinement_instInhabitedInput___closed__1;
static lean_object* _init_l_VSEL_Refinement_instInhabitedInput___closed__1() {
_start:
{
lean_object* x_1; 
x_1 = lean_mk_string_from_bytes("", 0);
return x_1;
}
}
static lean_object* _init_l_VSEL_Refinement_instInhabitedInput___closed__2() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = lean_box(0);
x_2 = l_VSEL_Refinement_instInhabitedInput___closed__1;
x_3 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_3, 0, x_2);
lean_ctor_set(x_3, 1, x_1);
return x_3;
}
}
static lean_object* _init_l_VSEL_Refinement_instInhabitedInput___closed__3() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_box(0);
x_2 = lean_alloc_ctor(0, 2, 0);
lean_ctor_set(x_2, 0, x_1);
lean_ctor_set(x_2, 1, x_1);
return x_2;
}
}
static lean_object* _init_l_VSEL_Refinement_instInhabitedInput___closed__4() {
_start:
{
uint8_t x_1; lean_object* x_2; lean_object* x_3; lean_object* x_4; 
x_1 = 0;
x_2 = lean_unsigned_to_nat(32u);
x_3 = lean_box(x_1);
x_4 = l_List_replicateTR___rarg(x_2, x_3);
return x_4;
}
}
static lean_object* _init_l_VSEL_Refinement_instInhabitedInput___closed__5() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; lean_object* x_4; lean_object* x_5; 
x_1 = lean_box(0);
x_2 = l_VSEL_Refinement_instInhabitedInput___closed__3;
x_3 = lean_unsigned_to_nat(0u);
x_4 = l_VSEL_Refinement_instInhabitedInput___closed__4;
x_5 = lean_alloc_ctor(0, 5, 0);
lean_ctor_set(x_5, 0, x_1);
lean_ctor_set(x_5, 1, x_1);
lean_ctor_set(x_5, 2, x_2);
lean_ctor_set(x_5, 3, x_3);
lean_ctor_set(x_5, 4, x_4);
return x_5;
}
}
static lean_object* _init_l_VSEL_Refinement_instInhabitedInput___closed__6() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; lean_object* x_4; 
x_1 = lean_box(0);
x_2 = l_VSEL_Refinement_instInhabitedInput___closed__2;
x_3 = l_VSEL_Refinement_instInhabitedInput___closed__5;
x_4 = lean_alloc_ctor(0, 3, 0);
lean_ctor_set(x_4, 0, x_2);
lean_ctor_set(x_4, 1, x_3);
lean_ctor_set(x_4, 2, x_1);
return x_4;
}
}
static lean_object* _init_l_VSEL_Refinement_instInhabitedInput() {
_start:
{
lean_object* x_1; 
x_1 = l_VSEL_Refinement_instInhabitedInput___closed__6;
return x_1;
}
}
static lean_object* _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__1() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(0u);
x_2 = lean_alloc_ctor(0, 3, 0);
lean_ctor_set(x_2, 0, x_1);
lean_ctor_set(x_2, 1, x_1);
lean_ctor_set(x_2, 2, x_1);
return x_2;
}
}
static lean_object* _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__2() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; lean_object* x_4; 
x_1 = lean_box(0);
x_2 = l_VSEL_Refinement_SIR__to__Formal__State___closed__1;
x_3 = lean_unsigned_to_nat(0u);
x_4 = lean_alloc_ctor(0, 3, 0);
lean_ctor_set(x_4, 0, x_2);
lean_ctor_set(x_4, 1, x_3);
lean_ctor_set(x_4, 2, x_1);
return x_4;
}
}
static lean_object* _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__3() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = lean_box(0);
x_2 = l_VSEL_Refinement_SIR__to__Formal__State___closed__2;
x_3 = lean_alloc_ctor(0, 3, 0);
lean_ctor_set(x_3, 0, x_1);
lean_ctor_set(x_3, 1, x_1);
lean_ctor_set(x_3, 2, x_2);
return x_3;
}
}
static lean_object* _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__4() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = lean_box(0);
x_2 = l_VSEL_Refinement_instInhabitedInput___closed__4;
x_3 = lean_alloc_ctor(0, 3, 0);
lean_ctor_set(x_3, 0, x_2);
lean_ctor_set(x_3, 1, x_1);
lean_ctor_set(x_3, 2, x_1);
return x_3;
}
}
static lean_object* _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__5() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = lean_unsigned_to_nat(0u);
x_2 = l_VSEL_Refinement_instInhabitedInput___closed__4;
x_3 = lean_alloc_ctor(0, 3, 0);
lean_ctor_set(x_3, 0, x_1);
lean_ctor_set(x_3, 1, x_1);
lean_ctor_set(x_3, 2, x_2);
return x_3;
}
}
static lean_object* _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__6() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = lean_box(0);
x_2 = lean_unsigned_to_nat(0u);
x_3 = lean_alloc_ctor(0, 3, 0);
lean_ctor_set(x_3, 0, x_2);
lean_ctor_set(x_3, 1, x_2);
lean_ctor_set(x_3, 2, x_1);
return x_3;
}
}
static lean_object* _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__7() {
_start:
{
lean_object* x_1; lean_object* x_2; 
x_1 = lean_unsigned_to_nat(0u);
x_2 = lean_alloc_ctor(0, 3, 0);
lean_ctor_set(x_2, 0, x_1);
lean_ctor_set(x_2, 1, x_1);
lean_ctor_set(x_2, 2, x_1);
return x_2;
}
}
static lean_object* _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__8() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = lean_box(0);
x_2 = lean_unsigned_to_nat(0u);
x_3 = lean_alloc_ctor(0, 4, 0);
lean_ctor_set(x_3, 0, x_2);
lean_ctor_set(x_3, 1, x_2);
lean_ctor_set(x_3, 2, x_2);
lean_ctor_set(x_3, 3, x_1);
return x_3;
}
}
static lean_object* _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__9() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; lean_object* x_4; lean_object* x_5; 
x_1 = lean_box(0);
x_2 = l_VSEL_Refinement_SIR__to__Formal__State___closed__6;
x_3 = l_VSEL_Refinement_SIR__to__Formal__State___closed__7;
x_4 = l_VSEL_Refinement_SIR__to__Formal__State___closed__8;
x_5 = lean_alloc_ctor(0, 7, 0);
lean_ctor_set(x_5, 0, x_1);
lean_ctor_set(x_5, 1, x_1);
lean_ctor_set(x_5, 2, x_1);
lean_ctor_set(x_5, 3, x_2);
lean_ctor_set(x_5, 4, x_3);
lean_ctor_set(x_5, 5, x_1);
lean_ctor_set(x_5, 6, x_4);
return x_5;
}
}
static lean_object* _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__10() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; 
x_1 = lean_unsigned_to_nat(0u);
x_2 = l_VSEL_Refinement_instInhabitedInput___closed__4;
x_3 = lean_alloc_ctor(0, 4, 0);
lean_ctor_set(x_3, 0, x_1);
lean_ctor_set(x_3, 1, x_2);
lean_ctor_set(x_3, 2, x_1);
lean_ctor_set(x_3, 3, x_1);
return x_3;
}
}
static lean_object* _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__11() {
_start:
{
lean_object* x_1; lean_object* x_2; lean_object* x_3; lean_object* x_4; lean_object* x_5; lean_object* x_6; 
x_1 = l_VSEL_Refinement_SIR__to__Formal__State___closed__3;
x_2 = l_VSEL_Refinement_SIR__to__Formal__State___closed__4;
x_3 = l_VSEL_Refinement_SIR__to__Formal__State___closed__5;
x_4 = l_VSEL_Refinement_SIR__to__Formal__State___closed__9;
x_5 = l_VSEL_Refinement_SIR__to__Formal__State___closed__10;
x_6 = lean_alloc_ctor(0, 5, 0);
lean_ctor_set(x_6, 0, x_1);
lean_ctor_set(x_6, 1, x_2);
lean_ctor_set(x_6, 2, x_3);
lean_ctor_set(x_6, 3, x_4);
lean_ctor_set(x_6, 4, x_5);
return x_6;
}
}
LEAN_EXPORT lean_object* l_VSEL_Refinement_SIR__to__Formal__State(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_VSEL_Refinement_SIR__to__Formal__State___closed__11;
return x_2;
}
}
LEAN_EXPORT lean_object* l_VSEL_Refinement_SIR__to__Formal__State___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_VSEL_Refinement_SIR__to__Formal__State(x_1);
lean_dec(x_1);
return x_2;
}
}
LEAN_EXPORT lean_object* l_VSEL_Refinement_SIR__to__Formal__Input(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_VSEL_Refinement_instInhabitedInput___closed__6;
return x_2;
}
}
LEAN_EXPORT lean_object* l_VSEL_Refinement_SIR__to__Formal__Input___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_VSEL_Refinement_SIR__to__Formal__Input(x_1);
lean_dec(x_1);
return x_2;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_VSEL_Foundations_State(uint8_t builtin, lean_object*);
lean_object* initialize_VSEL_Foundations_Input(uint8_t builtin, lean_object*);
lean_object* initialize_VSEL_Foundations_Transition(uint8_t builtin, lean_object*);
lean_object* initialize_VSEL_Foundations_Invariants(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_VSEL_Refinement_FormalToSIR(uint8_t builtin, lean_object* w) {
lean_object * res;
if (_G_initialized) return lean_io_result_mk_ok(lean_box(0));
_G_initialized = true;
res = initialize_Init(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_VSEL_Foundations_State(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_VSEL_Foundations_Input(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_VSEL_Foundations_Transition(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_VSEL_Foundations_Invariants(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
l_VSEL_Refinement_instInhabitedInput___closed__1 = _init_l_VSEL_Refinement_instInhabitedInput___closed__1();
lean_mark_persistent(l_VSEL_Refinement_instInhabitedInput___closed__1);
l_VSEL_Refinement_instInhabitedInput___closed__2 = _init_l_VSEL_Refinement_instInhabitedInput___closed__2();
lean_mark_persistent(l_VSEL_Refinement_instInhabitedInput___closed__2);
l_VSEL_Refinement_instInhabitedInput___closed__3 = _init_l_VSEL_Refinement_instInhabitedInput___closed__3();
lean_mark_persistent(l_VSEL_Refinement_instInhabitedInput___closed__3);
l_VSEL_Refinement_instInhabitedInput___closed__4 = _init_l_VSEL_Refinement_instInhabitedInput___closed__4();
lean_mark_persistent(l_VSEL_Refinement_instInhabitedInput___closed__4);
l_VSEL_Refinement_instInhabitedInput___closed__5 = _init_l_VSEL_Refinement_instInhabitedInput___closed__5();
lean_mark_persistent(l_VSEL_Refinement_instInhabitedInput___closed__5);
l_VSEL_Refinement_instInhabitedInput___closed__6 = _init_l_VSEL_Refinement_instInhabitedInput___closed__6();
lean_mark_persistent(l_VSEL_Refinement_instInhabitedInput___closed__6);
l_VSEL_Refinement_instInhabitedInput = _init_l_VSEL_Refinement_instInhabitedInput();
lean_mark_persistent(l_VSEL_Refinement_instInhabitedInput);
l_VSEL_Refinement_SIR__to__Formal__State___closed__1 = _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__1();
lean_mark_persistent(l_VSEL_Refinement_SIR__to__Formal__State___closed__1);
l_VSEL_Refinement_SIR__to__Formal__State___closed__2 = _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__2();
lean_mark_persistent(l_VSEL_Refinement_SIR__to__Formal__State___closed__2);
l_VSEL_Refinement_SIR__to__Formal__State___closed__3 = _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__3();
lean_mark_persistent(l_VSEL_Refinement_SIR__to__Formal__State___closed__3);
l_VSEL_Refinement_SIR__to__Formal__State___closed__4 = _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__4();
lean_mark_persistent(l_VSEL_Refinement_SIR__to__Formal__State___closed__4);
l_VSEL_Refinement_SIR__to__Formal__State___closed__5 = _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__5();
lean_mark_persistent(l_VSEL_Refinement_SIR__to__Formal__State___closed__5);
l_VSEL_Refinement_SIR__to__Formal__State___closed__6 = _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__6();
lean_mark_persistent(l_VSEL_Refinement_SIR__to__Formal__State___closed__6);
l_VSEL_Refinement_SIR__to__Formal__State___closed__7 = _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__7();
lean_mark_persistent(l_VSEL_Refinement_SIR__to__Formal__State___closed__7);
l_VSEL_Refinement_SIR__to__Formal__State___closed__8 = _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__8();
lean_mark_persistent(l_VSEL_Refinement_SIR__to__Formal__State___closed__8);
l_VSEL_Refinement_SIR__to__Formal__State___closed__9 = _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__9();
lean_mark_persistent(l_VSEL_Refinement_SIR__to__Formal__State___closed__9);
l_VSEL_Refinement_SIR__to__Formal__State___closed__10 = _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__10();
lean_mark_persistent(l_VSEL_Refinement_SIR__to__Formal__State___closed__10);
l_VSEL_Refinement_SIR__to__Formal__State___closed__11 = _init_l_VSEL_Refinement_SIR__to__Formal__State___closed__11();
lean_mark_persistent(l_VSEL_Refinement_SIR__to__Formal__State___closed__11);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
