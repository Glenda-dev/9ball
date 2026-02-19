use crate::NineBallManager;
use crate::layout::{MANIFEST_ADDR, MANIFEST_SLOT};
use crate::{error, log};
use glenda::cap::{CapPtr, Endpoint, Reply};
use glenda::error::Error;
use glenda::interface::{InitService, MemoryService, ResourceService, SystemService};
use glenda::ipc::server::handle_call;
use glenda::ipc::{Badge, MsgTag, UTCB};
use glenda::protocol;
use glenda::protocol::resource::INIT_ENDPOINT;
use glenda::protocol::resource::ResourceType;

impl<'a> SystemService for NineBallManager<'a> {
    fn init(&mut self) -> Result<(), Error> {
        log!("Loading config...");
        let (frame, size) =
            self.res_client.get_config(Badge::null(), "init.json", MANIFEST_SLOT)?;
        self.res_client.mmap(Badge::null(), frame, MANIFEST_ADDR, size)?;
        let data = unsafe { core::slice::from_raw_parts(MANIFEST_ADDR as *const u8, size) };
        self.config = serde_json::from_slice(data).map_err(|_| Error::InvalidConfig)?;
        self.launch()?;
        Ok(())
    }
    fn listen(&mut self, ep: Endpoint, reply: CapPtr, recv: CapPtr) -> Result<(), Error> {
        self.endpoint = ep;
        self.reply = Reply::from(reply);
        self.recv = recv;
        self.res_client.register_cap(
            Badge::null(),
            ResourceType::Endpoint,
            INIT_ENDPOINT,
            ep.cap(),
        )?;
        Ok(())
    }
    fn run(&mut self) -> Result<(), Error> {
        if self.endpoint.cap().is_null() || self.reply.cap().is_null() || self.recv.is_null() {
            return Err(Error::NotInitialized);
        }
        self.running = true;
        while self.running {
            let mut utcb = unsafe { UTCB::new() };
            utcb.clear();
            utcb.set_reply_window(self.reply.cap());
            match self.endpoint.recv(&mut utcb) {
                Ok(b) => b,
                Err(e) => {
                    log!("Recv error: {:?}", e);
                    continue;
                }
            };

            let res = self.dispatch(&mut utcb);
            if let Err(e) = res {
                if e == Error::Success {
                    continue;
                }
                let badge = utcb.get_badge();
                error!("Failed to dispatch message for {}: {:?}", badge, e);
                utcb.set_msg_tag(MsgTag::err());
                utcb.set_mr(0, e as usize);
            }

            self.reply(&mut utcb)?;
        }
        Ok(())
    }
    fn dispatch(&mut self, utcb: &mut UTCB) -> Result<(), Error> {
        glenda::ipc_dispatch! {
            self, utcb,
            (protocol::INIT_PROTO, protocol::init::START) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let name = unsafe { u.read_str() }.map_err(|_| Error::InvalidArgs)?;
                    s.start_service(&name)
                })
            },
            (protocol::INIT_PROTO, protocol::init::STOP) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let name = unsafe { u.read_str() }.map_err(|_| Error::InvalidArgs)?;
                    s.stop_service(&name)
                })
            },
            (protocol::INIT_PROTO, protocol::init::RESTART) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let name = unsafe { u.read_str() }.map_err(|_| Error::InvalidArgs)?;
                    s.restart_service(&name)
                })
            },
            (protocol::INIT_PROTO, protocol::init::RELOAD) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let name = unsafe { u.read_str() }.map_err(|_| Error::InvalidArgs)?;
                    s.reload_service(&name)
                })
            },
            (protocol::INIT_PROTO, protocol::init::QUERY) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let name = unsafe { u.read_str() }.map_err(|_| Error::InvalidArgs)?;
                    let status = s.query_service(&name)?;
                    unsafe { u.write_postcard(&status).map_err(|_| Error::InvalidArgs) }
                })
            },
            (protocol::INIT_PROTO, protocol::init::LIST) => |s: &mut Self, u: &mut UTCB| {
                handle_call(u, |u| {
                    let services = s.list_services()?;
                    unsafe { u.write_postcard(&services).map_err(|_| Error::InvalidArgs) }
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
