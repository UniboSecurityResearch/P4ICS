use std::error::Error;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Instant;

use dnp3::app::{ConnectStrategy, NullListener};
use dnp3::link::{EndpointAddress, LinkErrorMode};
use dnp3::master::{
    AssociationConfig, AssociationHandle, AssociationHandler, AssociationInformation,
    Classes, MasterChannelConfig, ReadHandler, ReadRequest,
};
use dnp3::tcp::EndpointList;
use dnp3::tcp::tls::{spawn_master_tls_client, TlsClientConfig, MinTlsVersion};

// handler “no-op”
struct RH; impl ReadHandler for RH {}
struct AH; impl AssociationHandler for AH {}
struct AI; impl AssociationInformation for AI {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Indirizzi DNP3: master=1, outstation=102
    let master_addr = EndpointAddress::try_new(1)?;
    let outstation_addr = EndpointAddress::try_new(102)?;

    // Config TLS client (self-signed): fidati del certificato del server + usa cert/chiave del client
    let tls_config = TlsClientConfig::self_signed(
        Path::new("./server_cert.crt"), // certificato pubblico dell'OUTSTATION (server) da fidare
        Path::new("./cert.crt"),     // certificato pubblico del MASTER (client)
        Path::new("./key.key"),      // chiave privata del MASTER
        None,                                   // nessuna password
        MinTlsVersion::V12,
    )?;

    // Canale master **TLS** (nota: tls_config è l'ULTIMO argomento)
    let mut channel = spawn_master_tls_client(
        LinkErrorMode::Close,
        MasterChannelConfig::new(master_addr),
        EndpointList::new("192.168.100.102:20001".to_string(), &[]),
        ConnectStrategy::default(),
        NullListener::create(),
        tls_config,
    );

    // Associazione “quiet” (nessun poll automatico)
    let assoc_cfg = AssociationConfig::quiet();
    let mut association: AssociationHandle = channel
        .add_association(
            outstation_addr,
            assoc_cfg,
            Box::new(RH),
            Box::new(AH),
            Box::new(AI),
        )
        .await?;

    // Abilita il canale
    channel.enable().await?;

    // File output: un tempo in microsecondi per riga
    let file = File::create("tempi_richieste.txt")?;
    let mut writer = BufWriter::new(file);

    // 100000 letture Class 0 — ricrea la ReadRequest ogni volta (evita move)
    for _ in 0..100_000 {
        let t0 = Instant::now();
        association
            .read(ReadRequest::class_scan(Classes::class0()))
            .await?;
        let us = t0.elapsed().as_micros();
        writeln!(writer, "{}", us)?;
    }

    writer.flush()?;
    println!("TLS: 100000 letture completate -> tempi_richieste.txt");
    Ok(())
}

