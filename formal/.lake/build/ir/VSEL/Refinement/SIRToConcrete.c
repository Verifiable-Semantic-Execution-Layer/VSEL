// Lean compiler output
// Module: VSEL.Refinement.SIRToConcrete
// Imports: Init VSEL.Foundations.State VSEL.Foundations.Input VSEL.Foundations.Transition VSEL.Mapping.SemanticMapping VSEL.Mapping.Commutativity VSEL.Mapping.Observable
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
LEAN_EXPORT lean_object* l_VSEL_Refinement_Encode(lean_object*);
LEAN_EXPORT lean_object* l_VSEL_Refinement_Encode___boxed(lean_object*);
LEAN_EXPORT lean_object* l_VSEL_Refinement_Encode(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = lean_box(0);
return x_2;
}
}
LEAN_EXPORT lean_object* l_VSEL_Refinement_Encode___boxed(lean_object* x_1) {
_start:
{
lean_object* x_2; 
x_2 = l_VSEL_Refinement_Encode(x_1);
lean_dec(x_1);
return x_2;
}
}
lean_object* initialize_Init(uint8_t builtin, lean_object*);
lean_object* initialize_VSEL_Foundations_State(uint8_t builtin, lean_object*);
lean_object* initialize_VSEL_Foundations_Input(uint8_t builtin, lean_object*);
lean_object* initialize_VSEL_Foundations_Transition(uint8_t builtin, lean_object*);
lean_object* initialize_VSEL_Mapping_SemanticMapping(uint8_t builtin, lean_object*);
lean_object* initialize_VSEL_Mapping_Commutativity(uint8_t builtin, lean_object*);
lean_object* initialize_VSEL_Mapping_Observable(uint8_t builtin, lean_object*);
static bool _G_initialized = false;
LEAN_EXPORT lean_object* initialize_VSEL_Refinement_SIRToConcrete(uint8_t builtin, lean_object* w) {
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
res = initialize_VSEL_Mapping_SemanticMapping(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_VSEL_Mapping_Commutativity(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
res = initialize_VSEL_Mapping_Observable(builtin, lean_io_mk_world());
if (lean_io_result_is_error(res)) return res;
lean_dec_ref(res);
return lean_io_result_mk_ok(lean_box(0));
}
#ifdef __cplusplus
}
#endif
