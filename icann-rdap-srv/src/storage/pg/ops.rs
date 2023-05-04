use async_trait::async_trait;
use sqlx::{query, PgPool};
use tracing::{debug, info};

use crate::{
    error::RdapServerError,
    rdap::response::RdapServerResponse,
    storage::{StoreOps, TxHandle},
};

use super::{config::PgConfig, tx::PgTx};

#[derive(Clone)]
pub struct Pg {
    pg_pool: PgPool,
}

impl Pg {
    pub async fn new(config: PgConfig) -> Result<Self, RdapServerError> {
        let pg_pool = PgPool::connect(&config.db_url).await?;
        Ok(Self { pg_pool })
    }
}

#[async_trait]
impl StoreOps for Pg {
    async fn init(&self) -> Result<(), RdapServerError> {
        debug!("Testing database connection.");
        let mut conn = self.pg_pool.acquire().await?;
        query("select 1").fetch_one(&mut conn).await?;
        info!("Database connection test is successful.");
        Ok(())
    }
    async fn new_tx(&self) -> Result<Box<dyn TxHandle>, RdapServerError> {
        Ok(Box::new(PgTx::new(&self.pg_pool).await?))
    }

    async fn get_domain_by_ldh(&self, _ldh: &str) -> Result<RdapServerResponse, RdapServerError> {
        todo!()
    }

    async fn get_entity_by_handle(
        &self,
        _handle: &str,
    ) -> Result<RdapServerResponse, RdapServerError> {
        todo!()
    }
}