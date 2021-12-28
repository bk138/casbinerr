use anyhow::Result;
use casbin::{CoreApi, DefaultModel, Enforcer, RbacApi, FileAdapter};
use sqlx_adapter::SqlxAdapter;

#[actix_web::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();

    // works
    let model = DefaultModel::from_file("casbin_model.conf").await?;
    let adapter = FileAdapter::new("casbin_policy.conf");
    let mut enforcer = Enforcer::new(model, adapter).await?;

    enforcer
        .add_role_for_user("kurt", "data1_admin", None)
        .await
        .unwrap_or_default();

    enforcer.delete_user("kurt").await?;
    assert_eq!(
        vec![String::new(); 0],
        enforcer.get_roles_for_user("kurt", None)
    );

    // fails
    let model = DefaultModel::from_file("casbin_model.conf").await?;
    let adapter = SqlxAdapter::new(std::env::var("DATABASE_URL")?, 10).await?;
    let mut enforcer = Enforcer::new(model, adapter).await?;

    enforcer
        .add_role_for_user("kurt", "data2_admin", None)
        .await
        .unwrap_or_default();

    enforcer.delete_user("kurt").await?;
    assert_eq!(
        vec![String::new(); 0],
        enforcer.get_roles_for_user("kurt", None)
    );

    Ok(())
}
