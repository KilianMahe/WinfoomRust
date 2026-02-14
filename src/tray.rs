use std::sync::mpsc::{self, Receiver};

#[cfg(windows)]
use std::{
    cell::RefCell,
    os::windows::ffi::OsStrExt,
    path::PathBuf,
    ptr,
    sync::mpsc::Sender,
    thread,
};

#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DispatchMessageW, GetCursorPos,
    FindWindowW, GetMessageW, LoadIconW, LoadImageW, PostMessageW, PostQuitMessage, RegisterClassW,
    SetForegroundWindow, ShowWindow, TrackPopupMenu, TranslateMessage, HICON, IDI_APPLICATION, IMAGE_ICON,
    LR_DEFAULTSIZE, LR_LOADFROMFILE, MF_STRING, MSG, TPM_BOTTOMALIGN, TPM_LEFTALIGN,
    TPM_LEFTBUTTON, SW_RESTORE, WM_CLOSE, WM_COMMAND, WM_DESTROY, WM_LBUTTONUP, WM_RBUTTONUP, WM_USER,
    WNDCLASSW, WS_OVERLAPPEDWINDOW,
};

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM, LRESULT, POINT, WPARAM},
    System::LibraryLoader::GetModuleHandleW,
    UI::Shell::{Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW},
};

#[derive(Debug, Clone, Copy)]
pub enum TrayEvent {
    ShowWindow,
    ExitApp,
}

#[cfg(windows)]
pub struct TrayController {
    hwnd: isize,
    worker: Option<thread::JoinHandle<()>>,
}

#[cfg(not(windows))]
pub struct TrayController;

#[cfg(windows)]
const TRAY_CALLBACK_MSG: u32 = WM_USER + 1;
#[cfg(windows)]
const MENU_OPEN_ID: usize = 1001;
#[cfg(windows)]
const MENU_EXIT_ID: usize = 1002;

#[cfg(windows)]
struct TrayLoopState {
    hmenu: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
    tx: Sender<TrayEvent>,
    wake_ctx: eframe::egui::Context,
}

#[cfg(windows)]
thread_local! {
    static TRAY_STATE: RefCell<Option<TrayLoopState>> = const { RefCell::new(None) };
}

impl TrayController {
    #[cfg(windows)]
    fn tray_icon_handle() -> HICON {
        let mut candidates: Vec<PathBuf> = Vec::new();

        candidates.push(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets").join("icon.ico"));

        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd.join("assets").join("icon.ico"));
        }

        if let Ok(exe) = std::env::current_exe() {
            if let Some(exe_dir) = exe.parent() {
                candidates.push(exe_dir.join("assets").join("icon.ico"));
                candidates.push(exe_dir.join("icon.ico"));
            }
        }

        for icon_path in candidates {
            if !icon_path.exists() {
                continue;
            }

            let wide: Vec<u16> = icon_path
                .as_os_str()
                .to_string_lossy()
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let handle = unsafe {
                LoadImageW(
                    std::ptr::null_mut(),
                    wide.as_ptr(),
                    IMAGE_ICON,
                    0,
                    0,
                    LR_LOADFROMFILE | LR_DEFAULTSIZE,
                )
            };

            if !handle.is_null() {
                return handle;
            }
        }

        unsafe { LoadIconW(std::ptr::null_mut(), IDI_APPLICATION) }
    }

    #[cfg(windows)]
    pub fn create(wake_ctx: eframe::egui::Context) -> Result<(Self, Receiver<TrayEvent>), String> {
        let (tx, rx) = mpsc::channel::<TrayEvent>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<isize, String>>();
        let tx_thread = tx.clone();
        let wake_thread = wake_ctx.clone();

        let worker = thread::spawn(move || {
            if let Err(e) = run_tray_loop(tx_thread, wake_thread, ready_tx) {
                tracing::error!("Erreur boucle tray: {}", e);
            }
        });

        let hwnd = ready_rx
            .recv()
            .map_err(|_| "Impossible d'initialiser le thread tray".to_string())??;

        Ok((
            Self {
                hwnd,
                worker: Some(worker),
            },
            rx,
        ))
    }

    #[cfg(not(windows))]
    pub fn create(_wake_ctx: eframe::egui::Context) -> Result<(Self, Receiver<TrayEvent>), String> {
        let (_tx, rx) = mpsc::channel::<TrayEvent>();
        Ok((Self, rx))
    }
}

#[cfg(windows)]
impl Drop for TrayController {
    fn drop(&mut self) {
        unsafe {
            PostMessageW(self.hwnd as HWND, WM_CLOSE, 0, 0);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(windows)]
fn to_wide(text: &str) -> Vec<u16> {
    std::ffi::OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(windows)]
fn restore_main_window() {
    unsafe {
        let title = to_wide("WinfoomRust - Proxy Facade");
        let app_hwnd = FindWindowW(ptr::null(), title.as_ptr());
        if !app_hwnd.is_null() {
            ShowWindow(app_hwnd, SW_RESTORE);
            SetForegroundWindow(app_hwnd);
        }
    }
}

#[cfg(windows)]
unsafe extern "system" fn tray_wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND => {
            let menu_id = (wparam & 0xFFFF) as usize;
            TRAY_STATE.with(|state| {
                if let Some(state) = &*state.borrow() {
                    match menu_id {
                        MENU_OPEN_ID => {
                            restore_main_window();
                            let _ = state.tx.send(TrayEvent::ShowWindow);
                            state.wake_ctx.request_repaint();
                        }
                        MENU_EXIT_ID => {
                            let _ = state.tx.send(TrayEvent::ExitApp);
                            state.wake_ctx.request_repaint();
                            std::process::exit(0);
                        }
                        _ => {}
                    }
                }
            });
            0
        }
        TRAY_CALLBACK_MSG => {
            let mouse_msg = lparam as u32;
            if mouse_msg == WM_LBUTTONUP {
                restore_main_window();
                TRAY_STATE.with(|state| {
                    if let Some(state) = &*state.borrow() {
                        let _ = state.tx.send(TrayEvent::ShowWindow);
                        state.wake_ctx.request_repaint();
                    }
                });
                return 0;
            }

            if mouse_msg == WM_RBUTTONUP {
                let mut point = POINT { x: 0, y: 0 };
                if GetCursorPos(&mut point) != 0 {
                    SetForegroundWindow(hwnd);
                    TRAY_STATE.with(|state| {
                        if let Some(state) = &*state.borrow() {
                            TrackPopupMenu(
                                state.hmenu,
                                TPM_LEFTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                                point.x,
                                point.y,
                                0,
                                hwnd,
                                ptr::null(),
                            );
                        }
                    });
                }
                return 0;
            }

            0
        }
        WM_DESTROY => {
            let mut nid = std::mem::zeroed::<NOTIFYICONDATAW>();
            nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(windows)]
fn run_tray_loop(
    tx: Sender<TrayEvent>,
    wake_ctx: eframe::egui::Context,
    ready_tx: Sender<Result<isize, String>>,
) -> Result<(), String> {
    unsafe {
        let hinstance = GetModuleHandleW(ptr::null());
        if hinstance.is_null() {
            let _ = ready_tx.send(Err("GetModuleHandleW a échoué".to_string()));
            return Err("GetModuleHandleW a échoué".to_string());
        }

        let class_name = to_wide("winfoom_tray_window");
        let mut wnd_class = std::mem::zeroed::<WNDCLASSW>();
        wnd_class.lpfnWndProc = Some(tray_wnd_proc);
        wnd_class.hInstance = hinstance;
        wnd_class.lpszClassName = class_name.as_ptr();
        RegisterClassW(&wnd_class);

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            to_wide("WinfoomTray").as_ptr(),
            WS_OVERLAPPEDWINDOW,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            ptr::null(),
        );

        if hwnd.is_null() {
            let _ = ready_tx.send(Err("CreateWindowExW a échoué".to_string()));
            return Err("CreateWindowExW a échoué".to_string());
        }

        let hmenu = CreatePopupMenu();
        if hmenu.is_null() {
            let _ = ready_tx.send(Err("CreatePopupMenu a échoué".to_string()));
            return Err("CreatePopupMenu a échoué".to_string());
        }

        if AppendMenuW(hmenu, MF_STRING, MENU_OPEN_ID, to_wide("Ouvrir").as_ptr()) == 0 {
            let _ = ready_tx.send(Err("Ajout menu 'Ouvrir' impossible".to_string()));
            return Err("Ajout menu 'Ouvrir' impossible".to_string());
        }

        if AppendMenuW(hmenu, MF_STRING, MENU_EXIT_ID, to_wide("Quitter").as_ptr()) == 0 {
            let _ = ready_tx.send(Err("Ajout menu 'Quitter' impossible".to_string()));
            return Err("Ajout menu 'Quitter' impossible".to_string());
        }

        TRAY_STATE.with(|state| {
            *state.borrow_mut() = Some(TrayLoopState {
                hmenu,
                tx,
                wake_ctx,
            });
        });

        let mut nid = std::mem::zeroed::<NOTIFYICONDATAW>();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_MESSAGE | NIF_ICON;
        nid.uCallbackMessage = TRAY_CALLBACK_MSG;

        nid.hIcon = TrayController::tray_icon_handle();

        if Shell_NotifyIconW(NIM_ADD, &nid) == 0 {
            let _ = ready_tx.send(Err("Ajout icône tray impossible".to_string()));
            return Err("Ajout icône tray impossible".to_string());
        }

        let _ = ready_tx.send(Ok(hwnd as isize));

        let mut msg = std::mem::zeroed::<MSG>();
        while GetMessageW(&mut msg, ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    Ok(())
}
