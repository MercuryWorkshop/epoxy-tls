//! futures sink unfold with a close function
use core::{future::Future, pin::Pin};
use futures::{
	ready,
	task::{Context, Poll},
	Sink,
};
use pin_project_lite::pin_project;

pin_project! {
	/// UnfoldState used for stream and sink unfolds
	#[project = UnfoldStateProj]
	#[project_replace = UnfoldStateProjReplace]
	#[derive(Debug)]
	pub(crate) enum UnfoldState<T, Fut> {
		Value {
			value: T,
		},
		Future {
			#[pin]
			future: Fut,
		},
		Empty,
	}
}

impl<T, Fut> UnfoldState<T, Fut> {
	pub(crate) fn project_future(self: Pin<&mut Self>) -> Option<Pin<&mut Fut>> {
		match self.project() {
			UnfoldStateProj::Future { future } => Some(future),
			_ => None,
		}
	}

	pub(crate) fn take_value(self: Pin<&mut Self>) -> Option<T> {
		match &*self {
			Self::Value { .. } => match self.project_replace(Self::Empty) {
				UnfoldStateProjReplace::Value { value } => Some(value),
				_ => unreachable!(),
			},
			_ => None,
		}
	}
}

pin_project! {
	/// Sink for the [`unfold`] function.
	#[derive(Debug)]
	#[must_use = "sinks do nothing unless polled"]
	pub struct Unfold<T, F, R, CT, CF, CR> {
		function: F,
		close_function: CF,
		#[pin]
		state: UnfoldState<T, R>,
		#[pin]
		close_state: UnfoldState<CT, CR>
	}
}

pub(crate) fn unfold<T, F, R, CT, CF, CR, Item, E>(
	init: T,
	function: F,
	close_init: CT,
	close_function: CF,
) -> Unfold<T, F, R, CT, CF, CR>
where
	F: FnMut(T, Item) -> R,
	R: Future<Output = Result<T, E>>,
	CF: FnMut(CT) -> CR,
	CR: Future<Output = Result<CT, E>>,
{
	Unfold {
		function,
		close_function,
		state: UnfoldState::Value { value: init },
		close_state: UnfoldState::Value { value: close_init },
	}
}

impl<T, F, R, CT, CF, CR, Item, E> Sink<Item> for Unfold<T, F, R, CT, CF, CR>
where
	F: FnMut(T, Item) -> R,
	R: Future<Output = Result<T, E>>,
	CF: FnMut(CT) -> CR,
	CR: Future<Output = Result<CT, E>>,
{
	type Error = E;

	fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.poll_flush(cx)
	}

	fn start_send(self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
		let mut this = self.project();
		let future = match this.state.as_mut().take_value() {
			Some(value) => (this.function)(value, item),
			None => panic!("start_send called without poll_ready being called first"),
		};
		this.state.set(UnfoldState::Future { future });
		Ok(())
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		let mut this = self.project();
		Poll::Ready(if let Some(future) = this.state.as_mut().project_future() {
			match ready!(future.poll(cx)) {
				Ok(state) => {
					this.state.set(UnfoldState::Value { value: state });
					Ok(())
				}
				Err(err) => {
					this.state.set(UnfoldState::Empty);
					Err(err)
				}
			}
		} else {
			Ok(())
		})
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		ready!(self.as_mut().poll_flush(cx))?;
		let mut this = self.project();
		Poll::Ready(
			if let Some(future) = this.close_state.as_mut().project_future() {
				match ready!(future.poll(cx)) {
					Ok(state) => {
						this.close_state.set(UnfoldState::Value { value: state });
						Ok(())
					}
					Err(err) => {
						this.close_state.set(UnfoldState::Empty);
						Err(err)
					}
				}
			} else {
				let future = match this.close_state.as_mut().take_value() {
					Some(value) => (this.close_function)(value),
					None => panic!("start_send called without poll_ready being called first"),
				};
				this.close_state.set(UnfoldState::Future { future });
				return Poll::Pending;
			},
		)
	}
}
