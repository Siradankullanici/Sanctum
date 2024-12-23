//! A idiomatic Rust mutex type for Windows kernel driver development. This module is a work in progress
//! so not all mutex types will be implemented.

use core::{cell::UnsafeCell, ops::{Deref, DerefMut}};

use wdk_sys::{ntddk::{ExAcquireFastMutex, ExReleaseFastMutex, KeGetCurrentIrql, KeLowerIrql, KfRaiseIrql}, APC_LEVEL, DISPATCH_LEVEL, FAST_MUTEX};

use crate::ffi::ExInitializeFastMutex;

#[derive(Debug)]
pub enum DriverMutexError {
    IrqlTooHigh,
    IrqlNotAPCLevel,
}

pub struct FastMutex<T> {
    mutex: UnsafeCell<FAST_MUTEX>,
    inner: UnsafeCell<T>,
}

unsafe impl<T: Sync> Sync for FastMutex<T>{}

impl<T> FastMutex<T> {
    /// Internal initialisation of the inner FastMutex type.
    fn init(data: T) -> Result<Self, DriverMutexError> {

        if unsafe { KeGetCurrentIrql() } > DISPATCH_LEVEL as u8 {
            return Err(DriverMutexError::IrqlTooHigh)
        }

        let mut mutex = FAST_MUTEX::default();
        unsafe { ExInitializeFastMutex(&mut mutex) };
        let c = UnsafeCell::new(mutex);

        Ok(FastMutex {
            mutex: c,
            inner: UnsafeCell::new(data),
        })

    }

    pub fn new(data: T) -> Result<Self, DriverMutexError> {
        Self::init(data)
    }

    pub fn lock(&self) -> Result<FastMutexGuard<'_, T>, DriverMutexError> {
        if unsafe { KeGetCurrentIrql() } > APC_LEVEL as u8 {
            return Err(DriverMutexError::IrqlTooHigh);
        }

        unsafe { ExAcquireFastMutex(self.mutex.get()) };
         
        Ok(FastMutexGuard {
            fast_mutex: self
        })
    }
}

pub struct FastMutexGuard<'a, T> {
    fast_mutex: &'a FastMutex<T>,
}


impl<'a, T> Deref for FastMutexGuard<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.fast_mutex.inner.get() }
    }
}

impl<'a, T> DerefMut for FastMutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.fast_mutex.inner.get() }
    }
}

impl<'a, T> Drop for FastMutexGuard<'a, T> {
    fn drop(&mut self) {
        let mut irql_changed = false;

        let starting_irql = unsafe { KeGetCurrentIrql() };
        if starting_irql != APC_LEVEL as u8 {
            irql_changed = true;

            if starting_irql < APC_LEVEL as u8 {
                unsafe {
                    KfRaiseIrql(APC_LEVEL as u8);
                }
            } else {
                unsafe {
                    KeLowerIrql(APC_LEVEL as u8)
                }
            }
        }

        unsafe { ExReleaseFastMutex(self.fast_mutex.mutex.get()) }; 

        if irql_changed {
            if starting_irql < APC_LEVEL as u8 {
                unsafe {
                    KeLowerIrql(starting_irql);
                }
            } else {
                unsafe {
                    KfRaiseIrql(starting_irql);
                }
            }
        }
    }
}

// todo

// pub struct CriticalSection {}

// impl CriticalSection {
//     pub fn lock
// }