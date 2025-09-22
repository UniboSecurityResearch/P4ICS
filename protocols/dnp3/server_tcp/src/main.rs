use dnp3::app::{NullListener, Timestamp};
use dnp3::app::control::CommandStatus;
use dnp3::app::measurement::{AnalogInput as Analog, Flags, Time};
use dnp3::link::{EndpointAddress, LinkErrorMode};
use dnp3::outstation::{
    DefaultControlHandler, OutstationApplication, OutstationConfig, OutstationInformation,
};
use dnp3::outstation::database::{
    Add, Update, AnalogInputConfig as AnalogConfig, EventBufferConfig, EventClass, UpdateOptions,
};
use dnp3::tcp::{AddressFilter, Server};
use tokio::signal;

// implementazioni minime (no-op)
struct App;
impl OutstationApplication for App {}

struct Info;
impl OutstationInformation for Info {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // indirizzi di link: outstation=102, master=1
    let out_addr = EndpointAddress::try_new(102)?;
    let mstr_addr = EndpointAddress::try_new(1)?;

    // buffer eventi minimale
    let eb = EventBufferConfig::all_types(10);

    let config = OutstationConfig::new(out_addr, mstr_addr, eb);

    // server TCP su tutte le interfacce porta 20000 (puoi mettere "192.168.100.102:20000")
    let mut server = Server::new_tcp_server(LinkErrorMode::Close, "0.0.0.0:20000".parse()?);

    let outstation = server.add_outstation(
        config,
        Box::new(App),
        Box::new(Info),
        // NIENTE Box::new qui: with_status restituisce già Box<dyn ControlHandler>
        DefaultControlHandler::with_status(CommandStatus::NotSupported),
        NullListener::create(),
        AddressFilter::Any,
    )?;

    // definisci 1 Analog Input (indice 0) e impostalo a valore fisso 42.0
    outstation.transaction(|db| {
        db.add(0u16, Some(EventClass::Class1), AnalogConfig::default());
        db.update(
            0u16,
            &Analog::new(
                42.0,
                Flags::ONLINE,
                Time::Synchronized(Timestamp::zero()),
            ),
            UpdateOptions::default(),
        );
    });

    let _handle = server.bind().await?;
    println!("Outstation in ascolto su 0.0.0.0:20000 (link 102<->1). Ctrl+C per uscire.");
    signal::ctrl_c().await?;
    Ok(())
}

