import ida_kernwin
import ida_bytes
import ida_name
import ida_funcs
import idautils
import idc
import ida_idaapi
import ida_hexrays
import idaapi
import ida_typeinf
import ida_ida

class CreateStructHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def get_function_type(self, func_ea):
        """Get func type info"""
        tinfo = ida_typeinf.tinfo_t()
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc and cfunc.get_func_type(tinfo):
            return tinfo
        return None 

    def is_valid_function_ptr(self, ptr):
        """Check if it is a valid function pointer"""
        if not ida_bytes.is_loaded(ptr):
            return False

        func = ida_funcs.get_func(ptr)
        return func is not None and func.start_ea == ptr

    def activate(self, ctx):
        flag, start_ea, end_ea = ida_kernwin.read_range_selection(None)
        if not flag:
            print("No selection")
            return

        ptr_size = 4 if ida_ida.inf_is_32bit_exactly() else 8
        struct_name = f"Vtable_{start_ea:X}"
        tinfo = ida_typeinf.tinfo_t()
        members = []

        current_ea = start_ea
        offset = 0
        index = 0

        while current_ea < end_ea:
            if ptr_size == 8:
                ptr = ida_bytes.get_qword(current_ea)
            else:
                ptr = ida_bytes.get_dword(current_ea)

            udm = ida_typeinf.udt_member_t()
            udm.size = ptr_size
            #udm.offset = offset

            if self.is_valid_function_ptr(ptr):
                fname = ida_name.get_ea_name(ptr)
                if not fname:
                    fname = f"func_{index}"

                func_type = self.get_function_type(ptr)

                udm.name = fname
                udm.type = ida_typeinf.tinfo_t()
                if(func_type):
                    udm.type.create_ptr(func_type)  # 创建指向具体函数类型的指针
            else:
                udm.name = f"field_{offset:X}"
                udm.type = ida_typeinf.tinfo_t()
                if ptr_size == 8:
                    udm.type.create_simple_type(ida_typeinf.BTMT_UINT64)
                else:
                    udm.type.create_simple_type(ida_typeinf.BTF_UINT32)

            members.append(udm)

            current_ea += ptr_size
            offset += ptr_size
            index += 1

        udt_data = ida_typeinf.udt_type_data_t()
        for member in members:
            udt_data.push_back(member)

        tinfo.create_udt(udt_data, ida_typeinf.BTF_STRUCT)
        tinfo.set_named_type(None, struct_name, ida_typeinf.NTF_REPLACE | ida_typeinf.NTF_TYPE )
        ida_typeinf.apply_tinfo(start_ea, tinfo, ida_typeinf.TINFO_DEFINITE)

        print(f"Created vtable structure: {struct_name}")
        return tinfo

        return 1


    def update(self, ctx):
        #return idaapi.AST_ENABLE_ALWAYS
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_DISASM else ida_kernwin.AST_DISABLE_FOR_WIDGET

class CreateVTStructPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL 
    action_name = 'Create_VT_Struct:action'
    comment = "Create VTable struct from selection"
    help = "Create a VTable struct from the selected data in IDA View"
    wanted_name = "Create VT Struct Plugin"
    wanted_hotkey = ""
    
    def init(self):
        print("******** Create VT Struct Plugin ********")

        self.hooks = None
        action_desc = idaapi.action_desc_t(
            self.action_name,
            'Create VTable struct from selection',
            CreateStructHandler(),
            '',
            'Create VTable Struct from selection',
            170
        )

        # register action
        if idaapi.register_action(action_desc):
            print("******** Successfully registered Create_VT_Struct action ********")
            
            # Setting up a right-click menu hook for the disassembly interface
            class Hooks(ida_kernwin.UI_Hooks):
                def finish_populating_widget_popup(self, widget, popup):
                    if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
                        ida_kernwin.attach_action_to_popup(
                            widget,
                            popup,
                            CreateVTStructPlugin.action_name,
                            'Create VT Struct from selection'
                        )
            
            self.hooks = Hooks()
            self.hooks.hook()
            return ida_idaapi.PLUGIN_KEEP
        else:
            print("******** Failed to register Create_VT_Struct action ********")
        return ida_idaapi.PLUGIN_SKIP

    def run(self, arg):
        pass

    def term(self):
        print("******** Unload Create_VT_Struct Plugin ********")
        if self.hooks:
            self.hooks.unhook()
        ida_kernwin.unregister_action(self.action_name)

def PLUGIN_ENTRY():
    return CreateVTStructPlugin()