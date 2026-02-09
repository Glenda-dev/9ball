use crate::InitManager;
use crate::log;
use alloc::string::String;
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::{InitService, SystemService};
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
        if proto != protocol::INIT_PROTO {
            return Err(Error::InvalidProtocol);
        }
        match label {
            protocol::init::START => {
                let name =
                    unsafe { utcb.read_postcard::<String>() }.map_err(|_| Error::InvalidParam)?;
                self.start_service(name)?;
                utcb.set_msg_tag(MsgTag::new(
                    protocol::GENERIC_PROTO,
                    protocol::generic::REPLY,
                    MsgFlags::OK,
                ));
                Ok(())
            }
            protocol::init::STOP => {
                let name =
                    unsafe { utcb.read_postcard::<String>() }.map_err(|_| Error::InvalidParam)?;
                self.stop_service(name)?;
                utcb.set_msg_tag(MsgTag::new(
                    protocol::GENERIC_PROTO,
                    protocol::generic::REPLY,
                    MsgFlags::OK,
                ));
                Ok(())
            }
            protocol::init::RESTART => {
                let name =
                    unsafe { utcb.read_postcard::<String>() }.map_err(|_| Error::InvalidParam)?;
                self.restart_service(name)?;
                utcb.set_msg_tag(MsgTag::new(
                    protocol::GENERIC_PROTO,
                    protocol::generic::REPLY,
                    MsgFlags::OK,
                ));
                Ok(())
            }
            protocol::init::RELOAD => {
                let name =
                    unsafe { utcb.read_postcard::<String>() }.map_err(|_| Error::InvalidParam)?;
                self.reload_service(name)?;
                utcb.set_msg_tag(MsgTag::new(
                    protocol::GENERIC_PROTO,
                    protocol::generic::REPLY,
                    MsgFlags::OK,
                ));
                Ok(())
            }
            protocol::init::QUERY => {
                let name =
                    unsafe { utcb.read_postcard::<String>() }.map_err(|_| Error::InvalidParam)?;
                let status = self.query_service(name)?;
                unsafe { utcb.write_postcard(&status).map_err(|_| Error::InvalidParam) }?;
                utcb.set_msg_tag(MsgTag::new(
                    protocol::GENERIC_PROTO,
                    protocol::generic::REPLY,
                    MsgFlags::OK,
                ));
                Ok(())
            }
            protocol::init::LIST => {
                let services = self.list_services()?;
                unsafe { utcb.write_postcard(&services).map_err(|_| Error::InvalidParam) }?;
                utcb.set_msg_tag(MsgTag::new(
                    protocol::GENERIC_PROTO,
                    protocol::generic::REPLY,
                    MsgFlags::OK,
                ));
                Ok(())
            }
            _ => Err(Error::NotImplemented),
        }
    }
    fn reply(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        self.reply.reply(utcb)
    }
    fn stop(&mut self) {
        self.running = false;
    }
}
