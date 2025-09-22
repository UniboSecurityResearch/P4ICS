use std::error::Error;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::time::Instant;

use dnp3::app::{ConnectStrategy, NullListener};
use dnp3::link::{EndpointAddress, LinkErrorMode};
use dnp3::master::{
    AssociationConfig, AssociationHandle, AssociationHandler, AssociationInformation,
    Classes, MasterChannelConfig, ReadHandler, ReadRequest,
};
use dnp3::tcp::{spawn_master_tcp_client, EndpointList};

struct RH;  // ReadHandler no-op
impl ReadHandler for RH {}

struct AH;  // AssociationHandler no-op
impl AssociationHandler for AH {}

struct AI;  // AssociationInformation no-op
impl AssociationInformation for AI {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Indirizzi DNP3: master=1, outstation=102
    let master_addr = EndpointAddress::try_new(1)?;
    let outstation_addr = EndpointAddress::try_new(102)?;

    // Canale master TCP verso l’outstation
    let mut channel = spawn_master_tcp_client(
        LinkErrorMode::Close,
        MasterChannelConfig::new(master_addr),
        EndpointList::new("192.168.100.102:20000".to_string(), &[]),
        ConnectStrategy::default(),
        NullListener::create(),
    );

    // Associazione "quiet" (nessun poll automatico)
    let assoc_cfg = AssociationConfig::quiet();

    // Aggiungi associazione con handler no-op
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

    for _ in 0..100_000 {
        let t0 = Instant::now();
        association
            .read(ReadRequest::class_scan(Classes::class0()))
            .await?;
        let us = t0.elapsed().as_micros();
        writeln!(writer, "{}", us)?;
    }

    writer.flush()?;
    println!("OK: 100000 letture completate -> tempi_richieste.txt");
    Ok(())
}

