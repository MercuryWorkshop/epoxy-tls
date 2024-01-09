use crate::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::{Sink, Stream};
use penguin_mux_wasm::ws;
use pin_project_lite::pin_project;
use ws_stream_wasm::{WsErr, WsMessage, WsMeta, WsStream};

pin_project! {
    pub struct WsStreamWrapper {
        #[pin]
        ws: WsStream,
    }
}

impl WsStreamWrapper {
    pub async fn connect(
        url: impl AsRef<str>,
        protocols: impl Into<Option<Vec<&str>>>,
    ) -> Result<(Self, WsMeta), WsErr> {
        let (wsmeta, wsstream) = WsMeta::connect(url, protocols).await?;
        debug!("readystate {:?}", wsstream.ready_state());
        Ok((WsStreamWrapper { ws: wsstream }, wsmeta))
    }
}

impl Stream for WsStreamWrapper {
    type Item = Result<ws::Message, ws::Error>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        debug!("poll_next: {:?}", cx);
        let this = self.project();
        let ret = this.ws.poll_next(cx);
        match ret {
            Poll::Ready(item) => Poll::<Option<Self::Item>>::Ready(item.map(|x| {
                Ok(match x {
                    WsMessage::Text(txt) => ws::Message::Text(txt),
                    WsMessage::Binary(bin) => ws::Message::Binary(bin),
                })
            })),
            Poll::Pending => Poll::<Option<Self::Item>>::Pending,
        }
    }
}

fn wserr_to_ws_err(err: WsErr) -> ws::Error {
    debug!("err: {:?}", err);
    match err {
        WsErr::ConnectionNotOpen => ws::Error::AlreadyClosed,
        _ => ws::Error::Io(std::io::Error::other(format!("{:?}", err))),
    }
}

impl Sink<ws::Message> for WsStreamWrapper {
    type Error = ws::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        debug!("poll_ready: {:?}", cx);
        let this = self.project();
        let ret = this.ws.poll_ready(cx);
        match ret {
            Poll::Ready(item) => Poll::<Result<(), Self::Error>>::Ready(match item {
                Ok(_) => Ok(()),
                Err(err) => Err(wserr_to_ws_err(err)),
            }),
            Poll::Pending => Poll::<Result<(), Self::Error>>::Pending,
        }
    }

    fn start_send(self: Pin<&mut Self>, item: ws::Message) -> Result<(), Self::Error> {
        debug!("start_send: {:?}", item);
        use ws::Message::*;
        let item = match item {
            Text(txt) => WsMessage::Text(txt),
            Binary(bin) => WsMessage::Binary(bin),
            Close(_) => {
                debug!("closing");
                return match self.ws.wrapped().close() {
                    Ok(_) => Ok(()),
                    Err(err) => Err(ws::Error::Io(std::io::Error::other(format!(
                        "ws close err: {:?}",
                        err
                    )))),
                }
            }
            Ping(_) | Pong(_) | Frame(_) => return Ok(()),
        };
        let this = self.project();
        let ret = this.ws.start_send(item);
        match ret {
            Ok(_) => Ok(()),
            Err(err) => Err(wserr_to_ws_err(err)),
        }
    }

    // no point wrapping this as it's not going to do anything
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        debug!("poll closing {:?}", cx);
        let this = self.project();
        let ret = this.ws.poll_close(cx);
        match ret {
            Poll::Ready(item) => Poll::<Result<(), Self::Error>>::Ready(match item {
                Ok(_) => Ok(()),
                Err(err) => Err(wserr_to_ws_err(err)),
            }),
            Poll::Pending => Poll::<Result<(), Self::Error>>::Pending,
        }
    }
}

impl ws::WebSocketStream for WsStreamWrapper {
    fn ping_auto_pong(&self) -> bool {
        true
    }
}
