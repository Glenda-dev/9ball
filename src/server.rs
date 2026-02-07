use crate::InitManager;
use crate::log;
use alloc::string::String;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::{InitService, SystemService};
use glenda::ipc::{Badge, MsgFlags, MsgTag, UTCB};
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
            match self.endpoint.recv(self.reply.cap()) {
                Ok(b) => b,
                Err(e) => {
                    log!("Recv error: {:?}", e);
                    continue;
                }
            };
            let utcb = unsafe { UTCB::get() };
            let msg_info = utcb.msg_tag;
            let badge = utcb.badge;

            let res = self.dispatch(badge, msg_info);
            match res {
                Ok(_) => self.reply(MsgTag::new(
                    protocol::GENERIC_PROTO,
                    protocol::generic::REPLY,
                    MsgFlags::OK,
                ))?,
                Err(e) => match e {
                    Error::Success => {
                        continue;
                    }
                    Error::HasCap => self.reply(MsgTag::new(
                        protocol::GENERIC_PROTO,
                        protocol::generic::REPLY,
                        MsgFlags::OK | MsgFlags::HAS_CAP,
                    ))?,
                    _ => {
                        let utcb = unsafe { UTCB::get() };
                        utcb.mrs_regs[0] = e as usize;
                        self.reply(MsgTag::new(
                            protocol::GENERIC_PROTO,
                            protocol::generic::REPLY,
                            MsgFlags::ERROR,
                        ))?
                    }
                },
            }
        }
        Ok(())
    }
    fn dispatch(&mut self, badge: Badge, info: MsgTag) -> Result<(), Error> {
        let label = info.label();
        let proto = info.proto();
        let flags = info.flags();
        let utcb = unsafe { UTCB::get() };
        let msg = utcb.mrs_regs;

        log!(
            "Received message: badge={}, label={}, proto={}, flags={}, msg={:?}",
            badge,
            label,
            proto,
            flags,
            msg
        );
        if proto != protocol::INIT_PROTO {
            return Err(Error::InvalidProtocol);
        }
        match label {
            protocol::init::START => {
                let name =
                    unsafe { utcb.read_postcard::<String>().map_err(|_| Error::InvalidParam) }?;
                self.start_service(name)?;
                Ok(())
            }
            protocol::init::STOP => {
                let name =
                    unsafe { utcb.read_postcard::<String>().map_err(|_| Error::InvalidParam) }?;
                self.stop_service(name)?;
                Ok(())
            }
            protocol::init::RESTART => {
                let name =
                    unsafe { utcb.read_postcard::<String>().map_err(|_| Error::InvalidParam) }?;
                self.restart_service(name)?;
                Ok(())
            }
            protocol::init::RELOAD => {
                let name =
                    unsafe { utcb.read_postcard::<String>().map_err(|_| Error::InvalidParam) }?;
                self.reload_service(name)?;
                Ok(())
            }
            protocol::init::QUERY => {
                let name =
                    unsafe { utcb.read_postcard::<String>().map_err(|_| Error::InvalidParam) }?;
                let status = self.query_service(name)?;
                (unsafe { utcb.write_postcard(&status).map_err(|_| Error::InvalidParam) })?;
                Ok(())
            }
            protocol::init::LIST => {
                let services = self.list_services()?;
                (unsafe { utcb.write_postcard(&services).map_err(|_| Error::InvalidParam) })?;
                Ok(())
            }
            _ => Err(Error::NotImplemented),
        }
    }
    fn reply(&mut self, info: MsgTag) -> Result<(), Error> {
        self.reply.reply(info)
    }
    fn stop(&mut self) {
        self.running = false;
    }
}
