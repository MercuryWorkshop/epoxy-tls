use std::task::{Context, Waker};

use slab::Slab;

pub(crate) enum Waiter {
	Sleeping(Waker),
	Woken,
}

impl Waiter {
	pub fn new(cx: &mut Context<'_>) -> Self {
		Self::Sleeping(cx.waker().clone())
	}

	pub fn register(&mut self, cx: &mut Context<'_>) {
		match self {
			Self::Sleeping(x) => x.clone_from(cx.waker()),
			Self::Woken => *self = Self::Sleeping(cx.waker().clone()),
		}
	}

	pub fn take(&mut self) -> Option<Waker> {
		match std::mem::replace(self, Self::Woken) {
			Self::Sleeping(x) => Some(x),
			Self::Woken => None,
		}
	}
}

pub struct WaiterList {
	inner: Slab<Waiter>,
}

impl WaiterList {
	pub fn new() -> Self {
		Self { inner: Slab::new() }
	}

	pub fn add(&mut self, cx: &mut Context<'_>) -> usize {
		self.inner.insert(Waiter::new(cx))
	}

	pub fn update(&mut self, key: usize, cx: &mut Context<'_>) {
		self.inner
			.get_mut(key)
			.expect("task should never have invalid key")
			.register(cx);
	}

	pub fn remove(&mut self, key: usize) {
		self.inner.remove(key);
	}

	pub fn take_and_remove(&mut self, key: &mut Option<usize>) {
		if let Some(key) = key.take() {
			self.remove(key);
		}
	}

	pub fn take_all(&mut self) -> Vec<Waker> {
		self.inner.iter_mut().filter_map(|x| x.1.take()).collect()
	}
}
