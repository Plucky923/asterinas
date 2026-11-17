// SPDX-License-Identifier: MPL-2.0

use proc_macro2::TokenStream;
use quote::quote;
use syn::{ItemImpl, Result};

pub(super) fn expand(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    if !attr.is_empty() {
        return Err(syn::Error::new_spanned(
            attr,
            "user_event_handler does not take arguments",
        ));
    }

    let item: ItemImpl = syn::parse2(item)?;
    let Some((None, trait_path, _)) = &item.trait_ else {
        return Err(syn::Error::new_spanned(
            &item,
            "user_event_handler requires a UserEventHandler trait implementation",
        ));
    };
    if trait_path.segments.last().unwrap().ident != "UserEventHandler" {
        return Err(syn::Error::new_spanned(
            trait_path,
            "user_event_handler requires a UserEventHandler trait implementation",
        ));
    }
    if !item.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &item.generics,
            "the image's user-event handler must have a concrete type",
        ));
    }

    let handler_type = &item.self_ty;
    let cfg_attrs = item
        .attrs
        .iter()
        .filter(|attr| attr.path().is_ident("cfg") || attr.path().is_ident("cfg_attr"));

    Ok(quote! {
        #item

        #(#cfg_attrs)*
        const _: () = {
            extern crate alloc;

            // SAFETY: The image has one annotated handler implementation.
            // Duplicate definitions are rejected at link time.
            #[unsafe(no_mangle)]
            extern "Rust" fn __ostd_user_data_type_id() -> ::core::any::TypeId {
                ::core::any::TypeId::of::<alloc::sync::Arc<#handler_type>>()
            }

            #[unsafe(no_mangle)]
            extern "Rust" fn __ostd_user_local_data_type_id() -> ::core::any::TypeId {
                ::core::any::TypeId::of::<
                    <#handler_type as ::ostd::user::UserEventHandler>::LocalData,
                >()
            }

            #[unsafe(no_mangle)]
            unsafe extern "Rust" fn __ostd_user_init(
                data: *const (),
                local: *const (),
                task: &::ostd::task::CurrentTask,
                user_ctx: &mut ::ostd::arch::cpu::context::UserContext,
            ) -> bool {
                // SAFETY: OSTD checked the task's data and local_data types during construction.
                // The current task keeps both alive throughout the callback.
                let handler: &#handler_type = unsafe {
                    &*data.cast::<alloc::sync::Arc<#handler_type>>()
                };
                let local: &<#handler_type as ::ostd::user::UserEventHandler>::LocalData = unsafe {
                    &*local.cast::<<#handler_type as ::ostd::user::UserEventHandler>::LocalData>()
                };
                <#handler_type as ::ostd::user::UserEventHandler>::init(
                    handler, local, task, user_ctx,
                )
            }

            #[unsafe(no_mangle)]
            unsafe extern "Rust" fn __ostd_user_handle(
                data: *const (),
                local: *const (),
                task: &::ostd::task::CurrentTask,
                event: ::ostd::user::UserEvent,
                user_ctx: &mut ::ostd::arch::cpu::context::UserContext,
            ) -> bool {
                // SAFETY: OSTD checked the task's data and local_data types during construction.
                // The current task keeps both alive throughout the callback.
                let handler: &#handler_type = unsafe {
                    &*data.cast::<alloc::sync::Arc<#handler_type>>()
                };
                let local: &<#handler_type as ::ostd::user::UserEventHandler>::LocalData = unsafe {
                    &*local.cast::<<#handler_type as ::ostd::user::UserEventHandler>::LocalData>()
                };
                <#handler_type as ::ostd::user::UserEventHandler>::handle(
                    handler, local, task, event, user_ctx,
                )
            }

            #[unsafe(no_mangle)]
            unsafe extern "Rust" fn __ostd_user_has_kernel_event(
                data: *const (),
                local: *const (),
                task: &::ostd::task::CurrentTask,
            ) -> bool {
                // SAFETY: OSTD checked the task's data and local_data types during construction.
                // The current task keeps both alive throughout the callback.
                let handler: &#handler_type = unsafe {
                    &*data.cast::<alloc::sync::Arc<#handler_type>>()
                };
                let local: &<#handler_type as ::ostd::user::UserEventHandler>::LocalData = unsafe {
                    &*local.cast::<<#handler_type as ::ostd::user::UserEventHandler>::LocalData>()
                };
                <#handler_type as ::ostd::user::UserEventHandler>::has_kernel_event(
                    handler, local, task,
                )
            }

            #[unsafe(no_mangle)]
            unsafe extern "Rust" fn __ostd_user_pre_user_run(
                data: *const (),
                local: *const (),
                guard: &::ostd::irq::DisabledLocalIrqGuard,
            ) {
                // SAFETY: OSTD checked the task's data and local_data types during construction.
                // The current task keeps both alive throughout the callback.
                let handler: &#handler_type = unsafe {
                    &*data.cast::<alloc::sync::Arc<#handler_type>>()
                };
                let local: &<#handler_type as ::ostd::user::UserEventHandler>::LocalData = unsafe {
                    &*local.cast::<<#handler_type as ::ostd::user::UserEventHandler>::LocalData>()
                };
                <#handler_type as ::ostd::user::UserEventHandler>::pre_user_run(
                    handler, local, guard,
                );
            }
        };
    })
}
