use crate::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::Stream;
use hyper::body::Body;
use pin_project_lite::pin_project;

pin_project! {
    pub struct IncomingBody {
        #[pin]
        incoming: hyper::body::Incoming,
    }
}

impl IncomingBody {
    pub fn new(incoming: hyper::body::Incoming) -> IncomingBody {
        IncomingBody { incoming }
    }
}

impl Stream for IncomingBody {
    type Item = std::io::Result<Bytes>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.project();
        let ret = this.incoming.poll_frame(cx);
        match ret {
            Poll::Ready(item) => Poll::<Option<Self::Item>>::Ready(match item {
                Some(frame) => frame
                    .map(|x| {
                        x.into_data().map_err(|_| std::io::Error::other("not data frame"))
                    })
                    .ok(),
                None => None,
            }),
            Poll::Pending => Poll::<Option<Self::Item>>::Pending,
        }
    }
}
