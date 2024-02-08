//! futures sink unfold with a close function
use core::{future::Future, pin::Pin};
use futures::ready;
use futures::task::{Context, Poll};
use futures::Sink;
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
    pub struct Unfold<T, F, FC, R> {
        function: F,
        close_function: FC,
        #[pin]
        state: UnfoldState<T, R>,
    }
}

pub(crate) fn unfold<T, F, FC, R, Item, E>(init: T, function: F, close_function: FC) -> Unfold<T, F, FC, R>
where
    F: FnMut(T, Item) -> R,
    R: Future<Output = Result<T, E>>,
    FC: Fn() -> Result<(), E>,
{
    Unfold { function, close_function, state: UnfoldState::Value { value: init } }
}

impl<T, F, FC, R, Item, E> Sink<Item> for Unfold<T, F, FC, R>
where
    F: FnMut(T, Item) -> R,
    R: Future<Output = Result<T, E>>,
    FC: Fn() -> Result<(), E>,
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
        Poll::Ready((self.close_function)())
    }
}
