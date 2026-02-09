use crate::InitManager;
use crate::log;
use alloc::string::String;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::{InitService, SystemService};
use glenda::ipc::server::handle_call;
use glenda::ipc::{MsgFlags, MsgTag, UTCB};
use glenda::protocol;

impl SystemService for InitManager {
    fn init(&mut self) -> Result<(), Error> {
        self.launch()?;
        Ok(())
    }
    fn listen(&mut self, ep: Endpoint, reply: CapPtr) -> Result<(), Error> {
        self.endpoint = ep;
        self.reply = Reply::from(reply);
        Ok(())
    }
    fn run(&mut self) -> Result<(), Error> {
        if self.endpoint.cap().is_null() || self.reply.cap().is_null() {
            return Err(Error::NotInitialized);
        }
        self.running = true;
        while self.running {
            let mut utcb = unsafe { UTCB::new() };
            match self.endpoint.recv(&mut utcb) {
                Ok(b) => b,
                Err(e) => {
                    log!("Recv error: {:?}", e);
                    continue;
                }
            };

            let res = self.dispatch(&mut utcb);
            if let Err(e) = res {
                match e {
                    Error::Success => {
                        continue;
                    }
                    Error::HasCap => {
                        utcb.set_msg_tag(MsgTag::new(
                            protocol::GENERIC_PROTO,
                            protocol::generic::REPLY,
                            MsgFlags::OK | MsgFlags::HAS_CAP,
                        ));
                    }
                    _ => {
                        utcb.set_mr(0, e as usize);
                        utcb.set_msg_tag(MsgTag::new(
                            protocol::GENERIC_PROTO,
                            protocol::generic::REPLY,
                            MsgFlags::ERROR,
                        ));
                    }
                }
            }

            self.reply(&mut utcb)?;
        }
        Ok(())
    }
    fn dispatch(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        let badge = utcb.get_badge();
        let info = utcb.get_msg_tag();
        let label = info.label();
        let proto = info.proto();
        let flags = info.flags();
        let msg = utcb.get_mrs();

        log!(
            "Received message: badge={}, label={}, proto={}, flags={}, msg={:?}",
            badge,
            label,
            proto,
            flags,
            msg
        );

        glenda::ipc_dispatch! {
            self, utcb,
            (protocol::INIT_PROTO, protocol::init::START) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let name = unsafe { u.read_postcard::<String>() }.map_err(|_| Error::InvalidParam)?;
                    s.start_service(name)
                })
            },
            (protocol::INIT_PROTO, protocol::init::STOP) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let name = unsafe { u.read_postcard::<String>() }.map_err(|_| Error::InvalidParam)?;
                    s.stop_service(name)
                })
            },
            (protocol::INIT_PROTO, protocol::init::RESTART) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let name = unsafe { u.read_postcard::<String>() }.map_err(|_| Error::InvalidParam)?;
                    s.restart_service(name)
                })
            },
            (protocol::INIT_PROTO, protocol::init::RELOAD) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let name = unsafe { u.read_postcard::<String>() }.map_err(|_| Error::InvalidParam)?;
                    s.reload_service(name)
                })
            },
            (protocol::INIT_PROTO, protocol::init::QUERY) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let name = unsafe { u.read_postcard::<String>() }.map_err(|_| Error::InvalidParam)?;
                    let status = s.query_service(name)?;
                    unsafe { u.write_postcard(&status).map_err(|_| Error::InvalidParam) }
                })
            },
            (protocol::INIT_PROTO, protocol::init::LIST) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let services = s.list_services()?;
                    unsafe { u.write_postcard(&services).map_err(|_| Error::InvalidParam) }
                })
            },
        }
    }
    fn reply(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        self.reply.reply(utcb)
    }
    fn stop(&mut self) {
        self.running = false;
    }
}
