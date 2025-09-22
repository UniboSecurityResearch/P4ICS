use std::error::Error;
use std::path::Path;

use dnp3::tcp::{Server, AddressFilter};
use dnp3::tcp::tls::{TlsServerConfig, MinTlsVersion};

use dnp3::link::{EndpointAddress, LinkErrorMode};

use dnp3::app::NullListener;
use dnp3::app::measurement::{AnalogInput as Analog, Flags, Time};
use dnp3::app::Timestamp;

use dnp3::outstation::{
    OutstationApplication, OutstationInformation, OutstationConfig, DefaultControlHandler,
};
use dnp3::outstation::database::{
    Add, Update, EventBufferConfig, AnalogInputConfig as AnalogConfig, EventClass, UpdateOptions,
};

use tokio::signal;

// implementazioni minime (no-op) per i trait richiesti
struct App;
impl OutstationApplication for App {}

struct Info;
impl OutstationInformation for Info {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // TLS self-signed: path ai certificati/chiavi già esistenti
    let tls_config = TlsServerConfig::self_signed(
        Path::new("./client_cert.crt"),     // certificato del client MASTER da fidare
        Path::new("./cert.crt"), // certificato dell'OUTSTATION
        Path::new("./key.key"),  // chiave privata dell'OUTSTATION
        None,                                   // nessuna password della chiave
        MinTlsVersion::V12,
    )?;

    // Server TLS su IP fisso e porta 20001
    let mut server = Server::new_tls_server(
        LinkErrorMode::Close,
        "192.168.100.102:20001".parse()?,
        tls_config,
    );

    // Indirizzi di link: outstation=102, master=1
    let out_addr = EndpointAddress::try_new(102)?;
    let mstr_addr = EndpointAddress::try_new(1)?;

    // Buffer eventi minimo per tutti i tipi (10 a testa va bene per test)
    let eb = EventBufferConfig::all_types(10);

    // Config outstation
    let config = OutstationConfig::new(out_addr, mstr_addr, eb);

    // Istanzia outstation
    let outstation = server.add_outstation(
        config,
        Box::new(App),
        Box::new(Info),
        // questo ritorna già Box<dyn ControlHandler>
        DefaultControlHandler::create(),
        NullListener::create(),
        AddressFilter::Any,
    )?;

    // DB: un AnalogInput indice 0 a valore fisso 42.0
    outstation.transaction(|db| {
        db.add(0u16, Some(EventClass::Class1), AnalogConfig::default());
        db.update(
            0u16,
            &Analog::new(42.0, Flags::ONLINE, Time::Synchronized(Timestamp::zero())),
            UpdateOptions::default(),
        );
    });

    // Bind e wait Ctrl+C
    let _handle = server.bind().await?;
    println!("server_tls: outstation TLS su 192.168.100.102:20001 – Ctrl+C per uscire");
    signal::ctrl_c().await?;
    Ok(())
}

