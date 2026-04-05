fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("../icone.ico");
        res.compile().unwrap();
    }
    slint_build::compile("ui/appwindow.slint").unwrap();
}
