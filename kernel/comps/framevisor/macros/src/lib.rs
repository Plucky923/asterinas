// SPDX-License-Identifier: MPL-2.0

#![deny(unsafe_code)]

use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

#[proc_macro_attribute]
pub fn main(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let main_fn = parse_macro_input!(item as ItemFn);

    let main_fn_name = &main_fn.sig.ident;

    quote!(
        pub extern "Rust" fn __ostd_main() -> ! {
            __ostd_dynamic_main();
            ostd::power::poweroff(ostd::power::ExitCode::Success);
        }

        pub extern "Rust" fn __ostd_dynamic_main() -> () {
            let _: () = #main_fn_name();
        }

        #[expect(unused)]
        #main_fn
    )
    .into()
}
