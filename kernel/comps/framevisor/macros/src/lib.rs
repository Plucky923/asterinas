// SPDX-License-Identifier: MPL-2.0
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn main(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let main_fn = parse_macro_input!(item as ItemFn);

    let main_fn_name = &main_fn.sig.ident;

    quote!(
        #[no_mangle]
        extern "Rust" fn __framevm_main() -> () {
            let _: () = #main_fn_name();
        }

        #[expect(unused)]
        #main_fn
    )
    .into()
}
