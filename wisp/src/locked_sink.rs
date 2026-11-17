//! unfair async mutex that doesn't have guards by default

use std::{
	cell::UnsafeCell,
	future::poll_fn,
	marker::PhantomData,
	ops::{Deref, DerefMut},
	pin::Pin,
	sync::{
		atomic::{AtomicBool, Ordering},
		Arc, Mutex, MutexGuard,
	},
	task::{Context, Poll},
};

use futures::Sink;

use crate::{waiters::WakerList, ws::{Payload, TransportWrite}};

// it would be nice to have type_alias_bounds but oh well
#[expect(type_alias_bounds)]
pub(crate) type LockedWebSocketWrite<I: TransportWrite> = LockedSink<I, Payload>;
#[expect(type_alias_bounds)]
pub type LockedWebSocketWriteGuard<I: TransportWrite> = LockedSinkGuard<I, Payload>;

enum LockStatus {
	/// was locked, you are now in the list
	Joined(usize),
	/// was locked, you were already in the list
	Waiting,
	/// was unlocked, lock is yours now
	Unlocked,
}

struct SinkState<S: Sink<I>, I> {
	sink: UnsafeCell<S>,
	locked: AtomicBool,
	waiters: Mutex<WakerList>,

	phantom: PhantomData<I>,
}

unsafe impl<S: Sink<I> + Send, I> Send for SinkState<S, I> {}
unsafe impl<S: Sink<I>, I> Sync for SinkState<S, I> {}

impl<S: Sink<I>, I> SinkState<S, I> {
	pub fn new(sink: S) -> Self {
		Self {
			sink: UnsafeCell::new(sink),
			locked: AtomicBool::new(false),
			waiters: Mutex::new(WakerList::new()),

			phantom: PhantomData,
		}
	}

	fn lock_waiters(&self) -> MutexGuard<'_, WakerList> {
		self.waiters.lock().expect("waiters mutex was poisoned")
	}

	/// caller must make sure they are the ones locking the sink
	#[expect(clippy::mut_from_ref)]
	pub unsafe fn get_unpin(&self) -> &mut S {
		// SAFETY: we are locked
		unsafe { &mut *self.sink.get() }
	}

	#[expect(clippy::mut_from_ref)]
	/// caller must make sure they are the ones locking the sink
	pub unsafe fn get(&self) -> Pin<&mut S> {
		// SAFETY: we are locked
		let inner = unsafe { self.get_unpin() };
		// SAFETY: we never touch the UnsafeCell
		unsafe { Pin::new_unchecked(inner) }
	}

	pub fn lock(&self, key: Option<usize>, cx: &mut Context<'_>) -> LockStatus {
		let old_state = self.locked.swap(true, Ordering::AcqRel);
		match (key, old_state) {
			(Some(key), true) => {
				self.lock_waiters().update(key, cx);
				LockStatus::Waiting
			}
			(None, true) => {
				let pos = self.lock_waiters().add(cx);
				LockStatus::Joined(pos)
			}
			(_, false) => LockStatus::Unlocked,
		}
	}

	pub fn unlock(&self) {
		let mut waiters = self.lock_waiters();
		self.locked.store(false, Ordering::Release);
		let wake = waiters.take_all();
		drop(waiters);

		for waker in wake {
			waker.wake();
		}
	}

	/// Release the sink without waking anyone.
	///
	/// Only for `unlock_and_wait`, which is handing the lock back *because the sink is not
	/// ready*. Waking the queue there would wake tasks that are waiting on that same
	/// not-ready sink, and each of them would wake the rest right back — see
	/// `LockedSink::unlock_and_wait`.
	pub fn unlock_silent(&self) {
		self.locked.store(false, Ordering::Release);
	}

	pub fn add_waiter(&self, cx: &mut Context<'_>) -> usize {
		self.lock_waiters().add(cx)
	}

	pub fn update_waiter(&self, key: usize, cx: &mut Context<'_>) {
		self.lock_waiters().update(key, cx);
	}

	pub fn remove(&self, key: usize) {
		let mut waiters = self.lock_waiters();
		waiters.remove(key);

		// A waiter that leaves may have been holding a wakeup handed to it by `unlock`.
		// If the sink is free there is no one left to call `unlock` again, so anyone still
		// sleeping would sleep forever. Pass it on.
		//
		// On the acquire path in `poll_lock` the sink is already locked (the atomic swap
		// happened in `lock`), so this costs nothing there.
		if self.locked.load(Ordering::Acquire) {
			return;
		}
		let wake = waiters.take_all();
		drop(waiters);

		for waker in wake {
			waker.wake();
		}
	}
}

pub(crate) struct LockedSink<S: Sink<I>, I> {
	inner: Arc<SinkState<S, I>>,

	pos: Option<usize>,
	locked: bool,
}

impl<S: Sink<I>, I> Clone for LockedSink<S, I> {
	fn clone(&self) -> Self {
		Self {
			inner: self.inner.clone(),

			pos: None,
			locked: false,
		}
	}
}

impl<S: Sink<I>, I> Drop for LockedSink<S, I> {
	fn drop(&mut self) {
		// Leaving a slot behind leaks a `Sleeping` waiter holding a dead waker, which
		// every later `unlock` then wakes for nothing.
		if let Some(pos) = self.pos.take() {
			self.inner.remove(pos);
		}
		self.unlock();
	}
}

impl<S: Sink<I>, I> LockedSink<S, I> {
	pub fn new(sink: S) -> Self {
		Self {
			inner: Arc::new(SinkState::new(sink)),

			pos: None,
			locked: false,
		}
	}

	pub fn poll_lock(&mut self, cx: &mut Context<'_>) -> Poll<()> {
		if self.locked {
			Poll::Ready(())
		} else {
			match self.inner.lock(self.pos, cx) {
				LockStatus::Joined(pos) => {
					self.pos = Some(pos);

					// make sure we haven't raced an unlock
					if matches!(self.inner.lock(self.pos, cx), LockStatus::Unlocked) {
						if let Some(pos) = self.pos.take() {
							self.inner.remove(pos);
						}
						self.locked = true;
						return Poll::Ready(());
					}

					Poll::Pending
				}
				LockStatus::Waiting => {
					// make sure we haven't raced an unlock
					if matches!(self.inner.lock(self.pos, cx), LockStatus::Unlocked) {
						if let Some(pos) = self.pos.take() {
							self.inner.remove(pos);
						}
						self.locked = true;
						return Poll::Ready(());
					}

					Poll::Pending
				}
				LockStatus::Unlocked => {
					if let Some(pos) = self.pos.take() {
						self.inner.remove(pos);
					}
					self.locked = true;
					Poll::Ready(())
				}
			}
		}
	}
	pub async fn lock(&mut self) {
		poll_fn(|cx| self.poll_lock(cx)).await;
	}

	pub fn unlock(&mut self) {
		if self.locked {
			self.locked = false;
			self.inner.unlock();
		}
	}

	/// Give the lock back from a `poll_*` that is returning `Pending`, staying queued for
	/// it.
	///
	/// The sink underneath holds exactly **one** waker. Epoxy's is a `wasm_streams`
	/// `IntoSink` whose `ready_fut`/`write_fut` are single `JsFuture`s, and polling a
	/// `JsFuture` replaces the waker it was last polled with. So a task that hands the
	/// lock back mid-operation can have its wakeup taken by whoever locks next, and is
	/// then unreachable: the sink no longer knows about it and it is in no queue. That
	/// showed up on the wire as a wisp stream sending CONNECT and never writing another
	/// byte while its siblings ran normally. Sitting in the waiter list means the next
	/// `unlock` brings it back whether or not its waker survived.
	///
	/// The lock is *not* simply held across `Pending` instead: nothing obliges a caller to
	/// re-poll the same method, and `futures-rustls` does exactly that — having written its
	/// `ClientHello` it abandons a pending `poll_flush` and reads instead. A held lock would
	/// never come back, deadlocking every other stream and the mux actor with it.
	///
	/// Releases the lock *without* waking the queue, unlike [`Self::unlock`]. We are only
	/// here because the sink itself is not ready, and everyone queued is waiting on that
	/// same sink, so waking them just has them find it not ready and wake us back — two
	/// writers on a stalled sink ping-pong forever and never make progress. Nobody is
	/// stranded by the silence: the sink is holding *our* waker right now (we polled it
	/// last), so we are the one it wakes when it opens, and the plain `unlock` that ends
	/// our operation is what drains the queue. If we are dropped before that, `Drop` ->
	/// `SinkState::remove` hands the wakeup on.
	///
	/// Queues before releasing, so an `unlock` racing us on another thread cannot wake the
	/// list in the window where we are in neither the list nor the lock.
	pub fn unlock_and_wait(&mut self, cx: &mut Context<'_>) {
		match self.pos {
			Some(pos) => self.inner.update_waiter(pos, cx),
			None => self.pos = Some(self.inner.add_waiter(cx)),
		}

		if self.locked {
			self.locked = false;
			self.inner.unlock_silent();
		}
	}

	#[expect(clippy::mut_from_ref)]
	pub fn get(&self) -> Pin<&mut S> {
		debug_assert!(self.locked);
		// SAFETY: we are locked
		unsafe { self.inner.get() }
	}

	/// Take the lock as an owned guard that unlocks when dropped.
	///
	/// Only safe to use where the guard is held across the whole operation, i.e. from an
	/// `async fn` that `.await`s on it. **Do not use this from a hand-written `poll_*`**:
	/// `ready!`-ing on the sink drops the guard on `Pending`, which releases the lock
	/// while the sink still holds your waker, and the next task to poll that sink will
	/// overwrite it. See `MuxStreamAsyncWrite::poll_write` for the full failure mode; use
	/// `poll_lock` + `get` + an explicit `unlock` on the ready paths instead.
	pub fn get_handle(&mut self) -> LockedSinkHandle<S, I> {
		debug_assert!(self.locked);
		self.locked = false;

		LockedSinkHandle {
			inner: self.inner.clone(),
		}
	}
	pub fn get_guard(&mut self) -> LockedSinkGuard<S, I> {
		debug_assert!(self.locked);
		self.locked = false;

		LockedSinkGuard {
			inner: self.inner.clone(),
		}
	}
}

// always locked sink "guard" of lockedsink
pub(crate) struct LockedSinkHandle<S: Sink<I>, I> {
	inner: Arc<SinkState<S, I>>,
}

impl<S: Sink<I>, I> Sink<I> for LockedSinkHandle<S, I> {
	type Error = S::Error;

	fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		unsafe { self.inner.get() }.poll_ready(cx)
	}

	fn start_send(self: Pin<&mut Self>, item: I) -> Result<(), Self::Error> {
		unsafe { self.inner.get() }.start_send(item)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		unsafe { self.inner.get() }.poll_flush(cx)
	}

	fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		unsafe { self.inner.get() }.poll_close(cx)
	}
}

impl<S: Sink<I>, I> Drop for LockedSinkHandle<S, I> {
	fn drop(&mut self) {
		self.inner.unlock();
	}
}

// always locked "guard" of lockedsink
pub struct LockedSinkGuard<S: Sink<I>, I> {
	inner: Arc<SinkState<S, I>>,
}

impl<S: Sink<I>, I> Deref for LockedSinkGuard<S, I> {
	type Target = S;

	fn deref(&self) -> &Self::Target {
		unsafe { &*self.inner.get_unpin() }
	}
}

impl<S: Sink<I> + Unpin, I> DerefMut for LockedSinkGuard<S, I> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		unsafe { self.inner.get_unpin() }
	}
}

impl<S: Sink<I>, I> LockedSinkGuard<S, I> {
	pub fn deref_pin(&mut self) -> Pin<&mut S> {
		unsafe { self.inner.get() }
	}
}

impl<S: Sink<I>, I> Drop for LockedSinkGuard<S, I> {
	fn drop(&mut self) {
		self.inner.unlock();
	}
}
