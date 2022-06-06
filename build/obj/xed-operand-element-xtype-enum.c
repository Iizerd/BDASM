/// @file xed-operand-element-xtype-enum.c

// This file was automatically generated.
// Do not edit this file.

#include <string.h>
#include <assert.h>
#include "xed-operand-element-xtype-enum.h"

typedef struct {
    const char* name;
    xed_operand_element_xtype_enum_t value;
} name_table_xed_operand_element_xtype_enum_t;
static const name_table_xed_operand_element_xtype_enum_t name_array_xed_operand_element_xtype_enum_t[] = {
{"INVALID", XED_OPERAND_XTYPE_INVALID},
{"2F16", XED_OPERAND_XTYPE_2F16},
{"B80", XED_OPERAND_XTYPE_B80},
{"BF16", XED_OPERAND_XTYPE_BF16},
{"F16", XED_OPERAND_XTYPE_F16},
{"F32", XED_OPERAND_XTYPE_F32},
{"F64", XED_OPERAND_XTYPE_F64},
{"F80", XED_OPERAND_XTYPE_F80},
{"I1", XED_OPERAND_XTYPE_I1},
{"I16", XED_OPERAND_XTYPE_I16},
{"I32", XED_OPERAND_XTYPE_I32},
{"I64", XED_OPERAND_XTYPE_I64},
{"I8", XED_OPERAND_XTYPE_I8},
{"INT", XED_OPERAND_XTYPE_INT},
{"STRUCT", XED_OPERAND_XTYPE_STRUCT},
{"U128", XED_OPERAND_XTYPE_U128},
{"U16", XED_OPERAND_XTYPE_U16},
{"U256", XED_OPERAND_XTYPE_U256},
{"U32", XED_OPERAND_XTYPE_U32},
{"U64", XED_OPERAND_XTYPE_U64},
{"U8", XED_OPERAND_XTYPE_U8},
{"UINT", XED_OPERAND_XTYPE_UINT},
{"VAR", XED_OPERAND_XTYPE_VAR},
{"LAST", XED_OPERAND_XTYPE_LAST},
{0, XED_OPERAND_XTYPE_LAST},
};

        
xed_operand_element_xtype_enum_t str2xed_operand_element_xtype_enum_t(const char* s)
{
   const name_table_xed_operand_element_xtype_enum_t* p = name_array_xed_operand_element_xtype_enum_t;
   while( p->name ) {
     if (strcmp(p->name,s) == 0) {
      return p->value;
     }
     p++;
   }
        

   return XED_OPERAND_XTYPE_INVALID;
}


const char* xed_operand_element_xtype_enum_t2str(const xed_operand_element_xtype_enum_t p)
{
   xed_operand_element_xtype_enum_t type_idx = p;
   if ( p > XED_OPERAND_XTYPE_LAST) type_idx = XED_OPERAND_XTYPE_LAST;
   return name_array_xed_operand_element_xtype_enum_t[type_idx].name;
}

xed_operand_element_xtype_enum_t xed_operand_element_xtype_enum_t_last(void) {
    return XED_OPERAND_XTYPE_LAST;
}
       
/*

Here is a skeleton switch statement embedded in a comment


  switch(p) {
  case XED_OPERAND_XTYPE_INVALID:
  case XED_OPERAND_XTYPE_2F16:
  case XED_OPERAND_XTYPE_B80:
  case XED_OPERAND_XTYPE_BF16:
  case XED_OPERAND_XTYPE_F16:
  case XED_OPERAND_XTYPE_F32:
  case XED_OPERAND_XTYPE_F64:
  case XED_OPERAND_XTYPE_F80:
  case XED_OPERAND_XTYPE_I1:
  case XED_OPERAND_XTYPE_I16:
  case XED_OPERAND_XTYPE_I32:
  case XED_OPERAND_XTYPE_I64:
  case XED_OPERAND_XTYPE_I8:
  case XED_OPERAND_XTYPE_INT:
  case XED_OPERAND_XTYPE_STRUCT:
  case XED_OPERAND_XTYPE_U128:
  case XED_OPERAND_XTYPE_U16:
  case XED_OPERAND_XTYPE_U256:
  case XED_OPERAND_XTYPE_U32:
  case XED_OPERAND_XTYPE_U64:
  case XED_OPERAND_XTYPE_U8:
  case XED_OPERAND_XTYPE_UINT:
  case XED_OPERAND_XTYPE_VAR:
  case XED_OPERAND_XTYPE_LAST:
  default:
     xed_assert(0);
  }
*/
