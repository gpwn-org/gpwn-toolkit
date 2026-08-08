//! Parse representative Realtek diagnostic output without connecting to an ONU.

use gpwn_core::{OnuState, parse_onu_state, parse_selection_expression};

fn main() -> gpwn_core::Result<()> {
    let (state, description) = parse_onu_state("ONU state: Operation State(O5)\r\n")?;
    assert_eq!(state, OnuState::O5);
    println!("ONU is {state}: {description}");

    let gem_ports = parse_selection_expression("1-3,7,9", 0, 4095)?;
    println!("selected GEM ports: {gem_ports:?}");
    Ok(())
}
