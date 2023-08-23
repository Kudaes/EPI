#[macro_use]
extern crate litcrypt;
use_litcrypt!();

use nanorand::{Rng, WyRand};
use std::mem::size_of;
use std::panic;
use std::{collections::HashMap, ptr};
use std::ffi::CString;
use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
use windows::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows::Win32::{Foundation::{HANDLE, HINSTANCE,UNICODE_STRING}, System::Threading::GetCurrentProcess};
use data::{ApiSetNamespace, ApiSetNamespaceEntry, ApiSetValueEntry, DLL_PROCESS_ATTACH, EAT, EntryPoint, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_READWRITE, 
    PVOID, PeMetadata, PS_ATTRIBUTE_LIST, PS_CREATE_INFO};
use libc::c_void;
use litcrypt::lc;
use winproc::Process;

static mut USE_IND_SYS: bool = false;

/// Enables or disables the use of indirect syscalls
pub fn use_indirect_sys(new_value: bool)
{
    unsafe 
    { 
        USE_IND_SYS = new_value; 
    }
}

/// Retrieves the memory address of a syscall instruction.
///
/// It expects the memory address of the function as a parameter, and 
/// it will iterate over each following byte until it finds the value 0x0F05.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
/// let nt_open_process = dinvoke::get_function_address(ntdll, "NtOpenProcess");
/// let syscall_addr = dinvoke::find_syscall_address(nt_open_process);
/// ```
pub fn find_syscall_address(address: usize) -> usize
{
    unsafe
    {
        let stub: [u8;2] = [ 0x0F, 0x05 ];
        let mut ptr:*mut u8 = address as *mut u8;
        for _i in 0..23
        {
            if *(ptr.add(1)) == stub[0] && *(ptr.add(2)) == stub[1]
            {
                return ptr.add(1) as usize;
            }

            ptr = ptr.add(1);
        }
    }

    0usize
}

/// Retrieves the base address of a module loaded in the current process.
///
/// In case that the module can't be found in the current process, it will
/// return 0.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     println!("The base address of ntdll.dll is 0x{:X}.", ntdll);
/// }
/// ```
pub fn get_module_base_address (module_name: &str) -> isize
{
    let process = Process::current();
    let modules = process.module_list().unwrap();
    for m in modules
    {
        if m.name().unwrap().to_lowercase().to_ascii_lowercase() == module_name.to_ascii_lowercase() ||
            m.path().unwrap().to_str().unwrap().to_ascii_lowercase() == module_name.to_ascii_lowercase()
        {
            let handle = m.handle();
            return handle as isize;
        }
    }

    0
}

/// Retrieves the address of an exported function from the specified module.
///
/// This functions is analogous to GetProcAddress from Win32. The exported 
/// function's address is obtained by walking and parsing the EAT of the  
/// specified module.
///
/// In case that the function's address can't be retrieved, it will return 0.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let addr = dinvoke::get_function_address(ntdll, "NtCreateThread");    
///     println!("The address where NtCreateThread is located at is 0x{:X}.", addr);
/// }
/// ```
pub fn get_function_address(module_base_address: isize, function: &str) -> isize {

    unsafe
    {
        let mut function_ptr:*mut i32 = ptr::null_mut();
        let pe_header = *((module_base_address + 0x3C) as *mut i32);
        let opt_header: isize = module_base_address + (pe_header as isize) + 0x18;
        let magic = *(opt_header as *mut i16);
        let p_export: isize;

        if magic == 0x010b 
        {
            p_export = opt_header + 0x60;
        } 
        else 
        {
            p_export = opt_header + 0x70;
        }

        let export_rva = *(p_export as *mut i32);
        let ordinal_base = *((module_base_address + export_rva as isize + 0x10) as *mut i32);
        let number_of_names = *((module_base_address + export_rva as isize + 0x18) as *mut i32);
        let functions_rva = *((module_base_address + export_rva as isize + 0x1C) as *mut i32);
        let names_rva = *((module_base_address + export_rva as isize + 0x20) as *mut i32);
        let ordinals_rva = *((module_base_address + export_rva as isize + 0x24) as *mut i32);

        for x in 0..number_of_names 
        {

            let address = *((module_base_address + names_rva as isize + x as isize * 4) as *mut i32);
            let mut function_name_ptr = (module_base_address + address as isize) as *mut u8;
            let mut function_name: String = "".to_string();

            while *function_name_ptr as char != '\0' // null byte
            { 
                function_name.push(*function_name_ptr as char);
                function_name_ptr = function_name_ptr.add(1);
            }

            if function_name.to_lowercase() == function.to_lowercase() 
            {
                let function_ordinal = *((module_base_address + ordinals_rva as isize + x as isize * 2) as *mut i16) as i32 + ordinal_base;
                let function_rva = *(((module_base_address + functions_rva as isize + (4 * (function_ordinal - ordinal_base)) as isize )) as *mut i32);
                function_ptr = (module_base_address + function_rva as isize) as *mut i32;

                function_ptr = get_forward_address(function_ptr as *mut u8) as *mut i32;
                
                break;
            }

        }

        let mut ret: isize = 0;

        if function_ptr != ptr::null_mut()
        {
            ret = function_ptr as isize;
        }
    
        ret

    }
}

fn get_forward_address(function_ptr: *mut u8) -> isize {
   
    unsafe 
    {
        let mut c = 100;
        let mut ptr = function_ptr.clone();
        let mut forwarded_names = "".to_string();

        loop 
        {
            if *ptr as char != '\0'
            {
                forwarded_names.push(*ptr as char);
            }
            else 
            {
                break;    
            }

            ptr = ptr.add(1);
            c = c - 1;

            // Assume there wont be an exported address with len > 100
            if c == 0
            {
                return function_ptr as isize;
            }

        }

        let values: Vec<&str> = forwarded_names.split(".").collect();
        if values.len() != 2
        {
            return function_ptr as isize;
        }

        let mut forwarded_module_name = values[0].to_string();
        let forwarded_export_name = values[1].to_string();

        let api_set = get_api_mapping();

        let prev_hook = panic::take_hook();
        panic::set_hook(Box::new(|_| {}));
        let result = panic::catch_unwind(|| {
            format!("{}{}",&forwarded_module_name[..forwarded_module_name.len() - 2], ".dll");
        });
        panic::set_hook(prev_hook);

        if result.is_err()
        {
            return function_ptr as isize;
        }

        let lookup_key = format!("{}{}",&forwarded_module_name[..forwarded_module_name.len() - 2], ".dll");

        if api_set.contains_key(&lookup_key)
        {
            forwarded_module_name = match api_set.get(&lookup_key) {
                Some(x) => x.to_string(),
                None => {forwarded_module_name}
            };
        }
        else 
        {
            forwarded_module_name = forwarded_module_name + ".dll";
        }

        let mut module = get_module_base_address(&forwarded_module_name);

        // If the module is not already loaded, we try to load it dynamically calling LoadLibraryA
        if module == 0
        {
            module = load_library_a(&forwarded_module_name);
        }

        if module != 0
        {
            return get_function_address(module, &forwarded_export_name);
        }

        function_ptr as isize
    }
}

pub fn get_api_mapping() -> HashMap<String,String> {

    unsafe 
    {
        let handle = GetCurrentProcess();
        let process_information: *mut c_void = std::mem::transmute(&PROCESS_BASIC_INFORMATION::default());
        let _ret = nt_query_information_process(
            handle, 
            0, 
            process_information,  
            size_of::<PROCESS_BASIC_INFORMATION>() as u32, 
            ptr::null_mut());
        
        let _r = close_handle(handle);

        let process_information_ptr: *mut PROCESS_BASIC_INFORMATION = std::mem::transmute(process_information);

        let api_set_map_offset:usize;

        if size_of::<usize>() == 4
        {
            api_set_map_offset = 0x38;
        }
        else 
        {
            api_set_map_offset = 0x68;
        }

        let mut api_set_dict: HashMap<String,String> = HashMap::new();

        let api_set_namespace_ptr = *(((*process_information_ptr).PebBaseAddress as usize + api_set_map_offset) as *mut isize);
        let api_set_namespace_ptr: *mut ApiSetNamespace = std::mem::transmute(api_set_namespace_ptr);
        let namespace = *api_set_namespace_ptr; 

        for i in 0..namespace.count
        {

            let set_entry_ptr = (api_set_namespace_ptr as usize + namespace.entry_offset as usize + (i * size_of::<ApiSetNamespaceEntry>() as i32) as usize) as *mut ApiSetNamespaceEntry;
            let set_entry = *set_entry_ptr;

            let mut api_set_entry_name_ptr = (api_set_namespace_ptr as usize + set_entry.name_offset as usize) as *mut u8;
            let mut api_set_entry_name: String = "".to_string();
            let mut j = 0;
            while j < (set_entry.name_length / 2 )
            {
                let c = *api_set_entry_name_ptr as char;
                if c != '\0' // Esto se podria meter en una funcion aparte
                {
                    api_set_entry_name.push(c);
                    j = j + 1;
                } 

                api_set_entry_name_ptr = api_set_entry_name_ptr.add(1); 

            }

            let api_set_entry_key = format!("{}{}",&api_set_entry_name[..api_set_entry_name.len()-2], ".dll");
            let mut set_value_ptr: *mut ApiSetValueEntry = ptr::null_mut();

            if set_entry.value_length == 1
            {
                let value = (api_set_namespace_ptr as usize + set_entry.value_offset as usize) as *mut u8;
                set_value_ptr = std::mem::transmute(value);
            }
            else if set_entry.value_length > 1
            {
                for x in 0..set_entry.value_length 
                {
                    let host_ptr = (api_set_entry_name_ptr as usize + set_entry.value_offset as usize + size_of::<ApiSetValueEntry>() as usize * x as usize) as *mut u8;
                    let mut c: u8 = u8::default();
                    let mut host: String = "".to_string();
                    while c as char != '\0'
                    {
                        c = *host_ptr;
                        if c as char != '\0'
                        {
                            host.push(c as char);
                        }
                    }

                    if host != api_set_entry_name
                    {
                        set_value_ptr = (api_set_namespace_ptr as usize + set_entry.value_offset as usize + size_of::<ApiSetValueEntry>() as usize * x as usize) as *mut ApiSetValueEntry;
                    }
                }

                if set_value_ptr == ptr::null_mut()
                {
                    set_value_ptr = (api_set_namespace_ptr as usize + set_entry.value_offset as usize) as *mut ApiSetValueEntry;
                }
            }

            let set_value = *set_value_ptr;
            let mut api_set_value: String = "".to_string();
            if set_value.value_count != 0
            {
                let mut value_ptr = (api_set_namespace_ptr as usize + set_value.value_offset as usize) as *mut u8;
                let mut r = 0;
                while r < (set_value.value_count / 2 )
                {
                    let c = *value_ptr as char;
                    if c != '\0' 
                    {
                        api_set_value.push(c);
                        r = r + 1;
                    } 
    
                    value_ptr = value_ptr.add(1); 
    
                }
            }

            api_set_dict.insert(api_set_entry_key, api_set_value);

        }

        api_set_dict

    }
}

/// Returns a BTreeMap<isize,String> composed of pairs (memory address, function name)
/// with all the Nt exported functions on ntdll.dll. 
///
/// This functions will only return valid data if the parameter passed is the base address of
/// ntdll.dll. This function is usefull to dynamically get a syscall id as it is shown in the
/// example.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let eat = dinvoke::get_ntdll_eat(ntdll);  
///     let mut j = 0;  
///     for (a,b) in eat.iter()
///     {
///         if b == "NtCreateThreadEx"
///         {
///             println!("The syscall id for NtCreateThreadEx is {}.",j);
///             break;
///         }
///         j = j + 1;
///     }
/// }
/// ```
pub fn get_ntdll_eat(module_base_address: isize) -> EAT {

    unsafe
    {
        let mut eat:EAT = EAT::default();

        let mut function_ptr:*mut i32;
        let pe_header = *((module_base_address + 0x3C) as *mut i32);
        let opt_header: isize = module_base_address + (pe_header as isize) + 0x18;
        let magic = *(opt_header as *mut i16);
        let p_export: isize;

        if magic == 0x010b 
        {
            p_export = opt_header + 0x60;
        } 
        else 
        {
            p_export = opt_header + 0x70;
        }

        let export_rva = *(p_export as *mut i32);
        let ordinal_base = *((module_base_address + export_rva as isize + 0x10) as *mut i32);
        let number_of_names = *((module_base_address + export_rva as isize + 0x18) as *mut i32);
        let functions_rva = *((module_base_address + export_rva as isize + 0x1C) as *mut i32);
        let names_rva = *((module_base_address + export_rva as isize + 0x20) as *mut i32);
        let ordinals_rva = *((module_base_address + export_rva as isize + 0x24) as *mut i32);

        for x in 0..number_of_names 
        {

            let address = *((module_base_address + names_rva as isize + x as isize * 4) as *mut i32);
            let mut function_name_ptr = (module_base_address + address as isize) as *mut u8;
            let mut function_name: String = "".to_string();

            while *function_name_ptr as char != '\0' // null byte
            { 
                function_name.push(*function_name_ptr as char);
                function_name_ptr = function_name_ptr.add(1);
            }

            if function_name.starts_with("Zw")
            {
                let function_ordinal = *((module_base_address + ordinals_rva as isize + x as isize * 2) as *mut i16) as i32 + ordinal_base;
                let function_rva = *(((module_base_address + functions_rva as isize + (4 * (function_ordinal - ordinal_base)) as isize )) as *mut i32);
                function_ptr = (module_base_address + function_rva as isize) as *mut i32;

                function_name = function_name.replace("Zw", "Nt");
                eat.insert(function_ptr as isize,function_name );
            }

        }
    
        eat

    }
}

/// Returns the syscall id that correspond to the function specified.
///
/// This functions will return -1 in case that the syscall id of the specified function
/// could not be retrieved.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let eat = dinvoke::get_ntdll_eat(ntdll);  
///     let id = dinvoke::get_syscall_id(eat, "NtCreateThreadEx");
///     
///     if id != -1
///     {
///         println!("The syscall id for NtCreateThreadEx is {}.",id);
///     }
/// }
/// ```
pub fn get_syscall_id(eat: &EAT, function_name: &str) -> i32 
{
    let mut i = 0;
    for (_a,b) in eat.iter()
    {
        if b == function_name
        {
            return i;
        }

        i = i + 1;
    }

    -1
}

/// Given a valid syscall id, it will allocate the required shellcode to execute 
/// that specific syscall.
///
/// This functions will return the memory address where the shellcode has been written. If any 
/// error has ocurred, it will return 0.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let eat = dinvoke::get_ntdll_eat(ntdll);  
///     let id = dinvoke::get_syscall_id(eat, "NtCreateThreadEx");
///     
///     if id != -1
///     {
///         let addr = dinvoke::prepare_syscall(id as u32);
///         println!("NtCreateThreadEx syscall ready to be executed at address 0x{:X}", addr);
///     }
/// }
/// ```
pub fn prepare_syscall(id: u32, eat: EAT) -> isize {

    let mut sh: [u8;21] = 
    [ 
        0x4C, 0x8B, 0xD1,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0xFF, 0xE3
    ];

    unsafe 
    {
        // We can't use indirect syscalls to prepare an indirect syscalls cause... infinite loops
        let previous_value = USE_IND_SYS;
        USE_IND_SYS = false;

        let mut ptr: *mut u8 = std::mem::transmute(&id);

        for i in 0..4
        {
            sh[4 + i] = *ptr;
            ptr = ptr.add(1);
        }
        let max_range = eat.len();
        let mut function = &"".to_string();
    
        let mut rng = WyRand::new();
        for s in eat.values()
        {
            let index = rng.generate_range(0_usize..=max_range) as usize;

            if index < max_range / 10
            {
                function = s;
                break;
            }
        }

        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        let mut function_addr = get_function_address(ntdll, function);

        if function_addr == 0
        {
            function_addr = get_function_address_by_ordinal(ntdll, id);
        }

        let syscall_addr = find_syscall_address(function_addr as usize);

        let mut syscall_ptr: *mut u8 = std::mem::transmute(&syscall_addr);

        for j in 0..8
        {
            sh[10 + j] = *syscall_ptr;
            syscall_ptr = syscall_ptr.add(1);
        }

        let handle = GetCurrentProcess();
        let b = usize::default();
        let base_address: *mut PVOID = std::mem::transmute(&b);
        let nsize: usize = sh.len() as usize;
        let s = nsize + 1;
        let size: *mut usize = std::mem::transmute(&s);
        let o = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&o);

        let ret = nt_allocate_virtual_memory(handle, base_address, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if ret != 0
        {
            USE_IND_SYS = previous_value;
            return 0;
        }

        let buffer: *mut c_void = std::mem::transmute(sh.as_ptr());
        let b = usize::default();
        let bytes_written: *mut usize = std::mem::transmute(&b);
        let ret = nt_write_virtual_memory(handle, *base_address, buffer, nsize, bytes_written);

        if ret != 0
        {
            USE_IND_SYS = previous_value;
            return 0;
        }

        let ret = nt_protect_virtual_memory(handle, base_address, size, PAGE_EXECUTE_READ, old_protection);
        let _r = close_handle(handle);
        USE_IND_SYS = previous_value;

        if ret != 0
        {
            return 0;
        }

        *base_address as isize
    }


}

/// Calls the module's entry point with the option DLL_ATTACH_PROCESS.
///
/// # Examples
///
/// ```ignore
///    let pe = manualmap::read_and_map_module("c:\\some\\random\\file.dll").unwrap();
///    let ret = dinvoke::call_module_entry_point(pe.0, pe.1);
/// 
///    match ret
///    {
///         Ok(()) => println!("Module entry point successfully executed."),
///         Err(e) => println!("Error ocurred: {}", e)
///    }
/// ```
pub fn call_module_entry_point(pe_info: PeMetadata, module_base_address: isize) -> Result<(), String> {

    let entry_point;
    if pe_info.is_32_bit 
    {
        entry_point = module_base_address + pe_info.opt_header_32.AddressOfEntryPoint as isize;
    }
    else 
    {
        entry_point = module_base_address + pe_info.opt_header_64.address_of_entry_point as isize;

    }

    unsafe 
    {
        let main: EntryPoint = std::mem::transmute(entry_point);
        let module = HINSTANCE {0: entry_point as isize};
        let ret = main(module, DLL_PROCESS_ATTACH, ptr::null_mut());

        if !ret.as_bool()
        {
            return Err(lc!("[x] Failed to call module's entry point (DllMain -> DLL_PROCESS_ATTACH)."));
        }

        Ok(())
    }
}

/// Retrieves the address of an exported function from the specified module by its ordinal.
///
/// In case that the function's address can't be retrieved, it will return 0.
///
/// This functions internally calls LdrGetProcedureAddress.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let ordinal: u32 = 8; 
///     let addr = dinvoke::get_function_address_ordinal(ntdll, ordinal);
///     if addr != 0
///     { 
///         println!("The function with ordinal 8 is located at 0x{:X}.", addr);
///     }
/// }
/// ```
pub fn get_function_address_by_ordinal(module_base_address: isize, ordinal: u32) -> isize {

    let ret = ldr_get_procedure_address(module_base_address, "", ordinal);

    ret    
}

/// Retrieves the address of an exported function from the specified module either by its name 
/// or by its ordinal number.
///
/// This functions internally calls LdrGetProcedureAddress.
///
/// In case that the function's address can't be retrieved, it will return 0.
///
/// # Examples
///
/// ```
/// let ntdll = dinvoke::get_module_base_address("ntdll.dll");
///
/// if ntdll != 0
/// {
///     let ordinal: u32 = 8; // Ordinal 8 represents the function RtlDispatchAPC
///     let addr = dinvoke::ldr_get_procedure_address(ntdll,"", 8);
///     if addr != 0
///     {
///         println!("The function with ordinal 8 is located at 0x{:X}.", addr);
///     }
/// }
/// ```
pub fn ldr_get_procedure_address (module_handle: isize, function_name: &str, ordinal: u32) -> isize {

    unsafe 
    {   
        let ret: Option<i32>;
        let func_ptr: data::LdrGetProcedureAddress;
        let hmodule: PVOID = std::mem::transmute(module_handle);
        let return_address: *mut c_void = std::mem::transmute(&usize::default());
        let return_address: *mut PVOID = std::mem::transmute(return_address);
        let mut fun_name: *mut String = std::mem::transmute(&String::default());

        if function_name == ""
        {
            fun_name = ptr::null_mut();
        }
        else 
        {
            *fun_name = function_name.to_string();
        }

        let module_base_address = get_module_base_address(&lc!("ntdll.dll")); 
        dynamic_invoke!(module_base_address,&lc!("LdrGetProcedureAddress"),func_ptr,ret,hmodule,fun_name,ordinal,return_address);

        match ret {
            Some(x) => 
            {
                if x == 0
                {
                    return *return_address as isize;
                } 
                else 
                {
                    return 0;
                }
            },
            None => return 0,
        }
    }
}

/// Loads and retrieves a module's base address by dynamically calling LoadLibraryA.
///
/// It will return either the module's base address or 0.
///
/// # Examples
///
/// ```
/// let ret = dinvoke::load_library_a("ntdll.dll");
///
/// if ret != 0 {println!("ntdll.dll base address is 0x{:X}.", addr);
/// ```
pub fn load_library_a(module: &str) -> isize {

    unsafe 
    {   
        let ret: Option<i32>;
        let func_ptr: data::RtlQueueWorkItem;
        let name = CString::new(module.to_string()).expect("");
        let module_name: PVOID = std::mem::transmute(name.as_ptr());
        let k32 = get_module_base_address(&lc!("kernel32.dll")); 
        let ntdll = get_module_base_address(&lc!("ntdll.dll")); 
        let load_library = get_function_address(k32, &lc!("LoadLibraryA")) as usize;
        let load_library = std::mem::transmute(load_library);
        dynamic_invoke!(ntdll,&lc!("RtlQueueWorkItem"),func_ptr,ret,load_library,module_name,0);


        match ret
        {
            Some(x) => 
            {
                if x != 0
                {
                    return 0;
                }
                else 
                {
                    use std::{thread, time};
                    let ten_millis = time::Duration::from_millis(500);
                    thread::sleep(ten_millis);
            
                    return get_module_base_address(module);
                }
            },
            None => { return 0; }
        }
        
       
       
    }     

}

/// Closes a HANDLE object.
///
/// It will return either a boolean value or an Err with a descriptive error message. If the function
/// fails the bool value returned will be false.
///
/// # Examples
///
/// ```
/// let pid = 792u32;
/// let handle = dinvoke::open_process(0x0040, 0, pid); //PROCESS_DUP_HANDLE access right.
/// 
/// if handle.0 != 0 && handle.0 != -1
/// {
///     let r = dinvoke::close_handle(handle);
///     if r
///     {
///         println!("Handle to process with id {} closed.", pid);
///     }
/// }
/// ```
pub fn close_handle(handle: HANDLE) -> bool {
    unsafe 
    {
        let ret: Option<i32>;
        let func_ptr: data::CloseHandle;
        let ntdll = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(ntdll,&lc!("CloseHandle"),func_ptr,ret,handle);

        match ret {
            Some(x) =>
            {
                if x == 0
                {
                    return false;
                }
                else 
                {
                    return true;
                }
            },
            None => return false,
        }
    }
}

/// Dynamically calls VirtualFree.
pub fn virtual_free(address: PVOID, size: usize, free_type: u32) -> bool {
    unsafe 
    {
        let ret: Option<bool>;
        let func_ptr: data::VirtualFree;
        let ntdll = get_module_base_address(&lc!("kernel32.dll"));
        dynamic_invoke!(ntdll,&lc!("VirtualFree"),func_ptr,ret,address,size,free_type);

        match ret {
            Some(x) =>
            {
                return x;
            },
            None => return false,
        }
    }
}

/// Dynamically calls NtWriteVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_write_virtual_memory (handle: HANDLE, base_address: PVOID, buffer: PVOID, size: usize, bytes_written: *mut usize) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtWriteVirtualMemory;
        if USE_IND_SYS
        {
            let func_name = &lc!("NtWriteVirtualMemory");
            execute_syscall!(func_name,func_ptr,ret,handle,base_address,buffer,size,bytes_written);
        }
        else 
        {
            let ntdll: isize = get_module_base_address(&lc!("ntdll.dll"));
            dynamic_invoke!(ntdll,&lc!("NtWriteVirtualMemory"),func_ptr,ret,handle,base_address,buffer,size,bytes_written);
        }

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }

}

/// Dynamically calls NtWriteVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_read_virtual_memory (handle: HANDLE, base_address: PVOID, buffer: PVOID, size: usize, bytes_written: *mut usize) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtReadVirtualMemory;

        if USE_IND_SYS
        {
            let func_name = &lc!("NtReadVirtualMemory");
            execute_syscall!(func_name,func_ptr,ret,handle,base_address,buffer,size,bytes_written);
        }   
        else 
        {
            let ntdll = get_module_base_address(&lc!("ntdll.dll"));
            dynamic_invoke!(ntdll,&lc!("NtReadVirtualMemory"),func_ptr,ret,handle,base_address,buffer,size,bytes_written);
        }

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }

}

/// Dynamically calls NtAllocateVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_allocate_virtual_memory (handle: HANDLE, base_address: *mut PVOID, zero_bits: usize, size: *mut usize, allocation_type: u32, protection: u32) -> i32 {

    unsafe 
    {
        let ret;
        let func_ptr: data::NtAllocateVirtualMemory;

        if USE_IND_SYS
        {
            let func_name = &lc!("NtAllocateVirtualMemory");
            execute_syscall!(func_name,func_ptr,ret,handle,base_address,zero_bits,size,allocation_type,protection);
        }
        else 
        {
            let ntdll = get_module_base_address(&lc!("ntdll.dll"));
            dynamic_invoke!(ntdll,&lc!("NtAllocateVirtualMemory"),func_ptr,ret,handle,base_address,zero_bits,size,allocation_type,protection);
        }
        
        match ret {
            Some(x) => return x,
            None => return -1,
        }
    }   
}

/// Dynamically calls NtProtectVirtualMemory.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_protect_virtual_memory (handle: HANDLE, base_address: *mut PVOID, size: *mut usize, new_protection: u32, old_protection: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtProtectVirtualMemory;

        if USE_IND_SYS
        {
            let func_name = &lc!("NtProtectVirtualMemory");
            execute_syscall!(func_name,func_ptr,ret,handle,base_address,size,new_protection,old_protection);
        }
        else 
        {
            let ntdll = get_module_base_address(&lc!("ntdll.dll"));
            dynamic_invoke!(ntdll,&lc!("NtProtectVirtualMemory"),func_ptr,ret,handle,base_address,size,new_protection,old_protection);
        }
       
        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls NtQueryInformationProcess.
///
/// It will return the NTSTATUS value returned by the call.
pub fn nt_query_information_process (handle: HANDLE, process_information_class: u32, process_information: PVOID, length: u32, return_length: *mut u32) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtQueryInformationProcess;
        if USE_IND_SYS
        {
            let func_name = &lc!("NtQueryInformationProcess");
            execute_syscall!(func_name,func_ptr,ret,handle,process_information_class,process_information,length,return_length);
        }
        else 
        {
            let ntdll = get_module_base_address(&lc!("ntdll.dll"));
            dynamic_invoke!(ntdll,&lc!("NtQueryInformationProcess"),func_ptr,ret,handle,process_information_class,process_information,length,return_length);    
        }

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls RtlAdjustPrivilege.
///
/// It will return the NTSTATUS value returned by the call.
pub fn rtl_adjust_privilege(privilege: u32, enable: u8, current_thread: u8, enabled: *mut u8) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::RtlAdjustPrivilege;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("RtlAdjustPrivilege"),func_ptr,ret,privilege,enable,current_thread,enabled);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls RtlInitUnicodeString.
///
/// It will return the NTSTATUS value returned by the call.
pub fn rtl_init_unicode_string (destination_string: *mut UNICODE_STRING, source_string: *const u16) -> () 
{
    unsafe
    {
        let _ret: Option<()>;
        let func_ptr: data::RtlInitUnicodeString;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("RtlInitUnicodeString"),func_ptr,_ret,destination_string, source_string);
    }
}

pub fn nt_create_user_process(process_handle: *mut HANDLE, thread_handle: *mut HANDLE, process_access: u32, thread_access: u32, object_attributes: *mut OBJECT_ATTRIBUTES,
    thread_object_attr: *mut OBJECT_ATTRIBUTES, process_flags: u32, thread_flags: u32, parameters: PVOID, create_info: *mut PS_CREATE_INFO, attr_list: *mut PS_ATTRIBUTE_LIST) -> i32 {
    
    unsafe 
    {
        let ret;
        let func_ptr: data::NtCreateUserProcess;
        let ntdll = get_module_base_address(&lc!("ntdll.dll"));
        dynamic_invoke!(ntdll,&lc!("NtCreateUserProcess"),func_ptr,ret,process_handle,thread_handle,process_access,thread_access,object_attributes,thread_object_attr,
                        process_flags,thread_flags,parameters,create_info,attr_list);

        match ret {
            Some(x) => return x,
            None => return -1,
        }
    } 
}

/// Dynamically calls an exported function from the specified module.
///
/// This macro will use the dinvoke crate functions to obtain an exported
/// function address of the specified module in the runtime by walking process structures 
/// and PE headers.
///
/// In case that this macro is used to call a dll entry point (DllMain), it will return true
/// or false (using the 3rd argument passed to the macro) depending on the success of the call.
/// In any other case, it will return the same data type that the called function would return
/// using the 4th argument passed to the macro.
///
/// # Example - Calling a dll entry point
///
/// ```ignore
/// let a = manualmap::read_and_map_module("c:\\some\\random\\file.dll").unwrap();
/// let ret: bool = false;
/// dinvoke::dynamic_invoke(&a.0, a.1, ret); // dinvoke::dynamic_invoke(&PeMetadata, isize, bool)
/// if ret { println!("Entry point successfully called.");}
/// ```
/// # Example - Dynamically calling LoadLibraryA
///
/// ```ignore
/// let kernel32 = manualmap::read_and_map_module("c:\\windows\\system32\\kernel32.dll").unwrap();
/// let mut ret:Option<HINSTANCE>;
/// let function_ptr: data::LoadLibraryA;
/// let name = CString::new("ntdll.dll").expect("CString::new failed");
/// let module_name = PSTR{0: name.as_ptr() as *mut u8};
/// //dinvoke::dynamic_invoke(isize,&str,<function_type>,Option<return_type>,[arguments])
/// dinvoke::dynamic_invoke(a.1, "LoadLibraryA", function_ptr, ret, module_name);
///
/// match ret {
///     Some(x) => if x.0 == 0 {println!("ntdll base address is 0x{:X}",x.0);},
///     None => println!("Error calling LdrGetProcedureAddress"),
/// }
/// ```
/// # Example - Dynamically calling with referenced arguments
///
/// ```ignore
/// let ptr = dinvoke::get_module_base_address("ntdll.dll");
/// let function_ptr: LdrGetProcedureAddress;
/// let ret: Option<i32>;
/// let hmodule: PVOID = std::mem::transmute(ptr);
/// let fun_name: *mut String = ptr::null_mut();
/// let ordinal = 8 as u32;
/// let return_address: *mut c_void = std::mem::transmute(&usize::default());
/// let return_address: *mut PVOID = std::mem::transmute(return_address);
/// //dinvoke::dynamic_invoke(isize,&str,<function_type>,Option<return_type>,[arguments])
/// dinvoke::dynamic_invoke!(ptr,"LdrGetProcedureAddress",function_ptr,ret,hmodule,fun_name,ordinal,return_address);
///
/// match ret {
///     Some(x) => if x == 0 {println!("RtlDispatchAPC is located at the address: 0x{:X}",*return_address as usize);},
///     None => println!("Error calling LdrGetProcedureAddress"),
/// }
/// ```
#[macro_export]
macro_rules! dynamic_invoke {

    ($a:expr, $b:expr, $c:expr) => {
        
        let ret = $crate::call_module_entry_point(&$a,$b);

        match ret {
            Ok(_) => $c = true,
            Err(_) => $c = false,
        }

    };

    ($a:expr, $b:expr, $c:expr, $d:expr, $($e:tt)*) => {

        let function_ptr = $crate::get_function_address($a, $b);
        if function_ptr != 0
        {
            $c = std::mem::transmute(function_ptr);
            $d = Some($c($($e)*));
        }
        else
        {
            $d = None;
        }

    };
}

/// Dynamically execute an indirect syscall.
///
/// This function expects as parameters the name of the Nt function whose syscall 
/// wants to be executed, a variable with the function header, an Option variable with the same
/// inner type that the original syscall would return and all the parameters expected by the syscall.
///
/// # Examples - Executing NtQueryInformationProcess with indirect syscall
///
/// ```ignore      
/// let function_type:NtQueryInformationProcess;
/// let mut ret: Option<i32> = None; //NtQueryInformationProcess returns a NTSTATUS, which is a i32.
/// let handle = GetCurrentProcess();
/// let process_information: *mut c_void = std::mem::transmute(&PROCESS_BASIC_INFORMATION::default()); 
/// let return_length: *mut u32 = std::mem::transmute(&u32::default());
/// dinvoke::execute_syscall!(
///     "NtQueryInformationProcess",
///     function_type,
///     ret,
///     handle,
///     0,
///     process_information,
///     size_of::<PROCESS_BASIC_INFORMATION>() as u32,
///     return_length
/// );
/// match ret {
///     Some(x) => if x == 0 {println!("Process information struct available at address 0x{:X}",process_information as usize);},
///     None => println!("Error executing direct syscall for NtQueryInformationProcess."),
/// }
/// ```
#[macro_export]
macro_rules! execute_syscall {

    ($a:expr, $b:expr, $c:expr, $($d:tt)*) => {

        let eat = $crate::get_ntdll_eat($crate::get_module_base_address("ntdll.dll"));
        let id = $crate::get_syscall_id(&eat, $a);
        if id != -1
        {
            let function_ptr = $crate::prepare_syscall(id as u32, eat);
            if function_ptr != 0
            {
                $b = std::mem::transmute(function_ptr);
                $c = Some($b($($d)*));
            }
            else
            {
                $c = None;
            }
            let ptr: PVOID = std::mem::transmute(function_ptr);
            $crate::virtual_free(ptr, 0, 0x00008000);
        }
        else
        {
            $c = None;
        }
    }
}
