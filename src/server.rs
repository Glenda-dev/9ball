use crate::InitManager;
use crate::log;
use alloc::string::String;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::{InitService, SystemService};
use glenda::ipc::{Badge, MsgArgs, MsgFlags, MsgTag, UTCB};
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
            let label = msg_info.label();
            let proto = msg_info.proto();
            let flags = msg_info.flags();
            let args = utcb.mrs_regs;

            let res = self.dispatch(badge, label, proto, flags, args);
            match res {
                Ok(ret) => self.reply(
                    protocol::GENERIC_PROTO,
                    protocol::generic::REPLY,
                    MsgFlags::OK,
                    ret,
                )?,
                Err(e) => match e {
                    Error::Success => {
                        continue;
                    }
                    Error::HasCap => self.reply(
                        protocol::GENERIC_PROTO,
                        protocol::generic::REPLY,
                        MsgFlags::OK | MsgFlags::HAS_CAP,
                        [0, 0, 0, 0, 0, 0, 0, 0],
                    )?,
                    _ => self.reply(
                        protocol::GENERIC_PROTO,
                        protocol::generic::REPLY,
                        MsgFlags::ERROR,
                        [e as usize, 0, 0, 0, 0, 0, 0, 0],
                    )?,
                },
            }
        }
        Ok(())
    }
    fn dispatch(
        &mut self,
        badge: Badge,
        label: usize,
        proto: usize,
        flags: MsgFlags,
        msg: MsgArgs,
    ) -> Result<MsgArgs, Error> {
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
        let utcb = unsafe { UTCB::get() };
        match label {
            protocol::init::START => {
                let name =
                    unsafe { utcb.read_postcard::<String>().map_err(|_| Error::InvalidParam) }?;
                self.start_service(name)?;
                Ok([0; 8])
            }
            protocol::init::STOP => {
                let name =
                    unsafe { utcb.read_postcard::<String>().map_err(|_| Error::InvalidParam) }?;
                self.stop_service(name)?;
                Ok([0; 8])
            }
            protocol::init::RESTART => {
                let name =
                    unsafe { utcb.read_postcard::<String>().map_err(|_| Error::InvalidParam) }?;
                self.restart_service(name)?;
                Ok([0; 8])
            }
            protocol::init::RELOAD => {
                let name =
                    unsafe { utcb.read_postcard::<String>().map_err(|_| Error::InvalidParam) }?;
                self.reload_service(name)?;
                Ok([0; 8])
            }
            protocol::init::QUERY => {
                let name =
                    unsafe { utcb.read_postcard::<String>().map_err(|_| Error::InvalidParam) }?;
                let status = self.query_service(name)?;
                (unsafe { utcb.write_postcard(&status).map_err(|_| Error::InvalidParam) })?;
                Ok([0, 0, 0, 0, 0, 0, 0, 0])
            }
            protocol::init::LIST => {
                let services = self.list_services()?;
                (unsafe { utcb.write_postcard(&services).map_err(|_| Error::InvalidParam) })?;
                Ok([0, 0, 0, 0, 0, 0, 0, 0])
            }
            _ => Err(Error::NotImplemented),
        }
    }
    fn reply(
        &mut self,
        label: usize,
        proto: usize,
        flags: MsgFlags,
        msg: MsgArgs,
    ) -> Result<(), Error> {
        let tag = MsgTag::new(proto, label, flags);
        self.reply.reply(tag, msg)
    }
    fn stop(&mut self) {
        self.running = false;
    }
}
