use std::{net::IpAddr, str::FromStr};

use axum::{
    extract::{Path, State},
    response::Response,
};
use cidr_utils::cidr::IpInet;
use tracing::debug;

use crate::{
    error::RdapServerError,
    rdap::{
        response::{ResponseUtil, BAD_REQUEST},
        ToBootStrap,
    },
    server::DynServiceState,
};

/// Gets a network object by the address path.
#[axum_macros::debug_handler]
#[tracing::instrument(level = "debug")]
pub(crate) async fn network_by_netid(
    Path(netid): Path<String>,
    state: State<DynServiceState>,
) -> Result<Response, RdapServerError> {
    if netid.contains('/') {
        debug!("getting network by cidr {netid}");
        if let Ok(cidr) = IpInet::from_str(&netid) {
            let storage = state.get_storage().await?;
            let network = storage.get_network_by_cidr(&cidr.to_string()).await?;
            if state.get_bootstrap() {
                Ok(network.to_ip_bootstrap(&netid).response())
            } else {
                Ok(network.response())
            }
        } else {
            Ok(BAD_REQUEST.response())
        }
    } else {
        debug!("getting network by ip address {netid}");
        let ip: Result<IpAddr, _> = netid.parse();
        if ip.is_err() {
            Ok(BAD_REQUEST.response())
        } else {
            let storage = state.get_storage().await?;
            let network = storage.get_network_by_ipaddr(&netid).await?;
            if state.get_bootstrap() {
                Ok(network.to_ip_bootstrap(&netid).response())
            } else {
                Ok(network.response())
            }
        }
    }
}
