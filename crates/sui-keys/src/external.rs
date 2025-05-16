use crate::keystore::{AccountKeystore, Alias};
use crate::random_names::random_name;
use anyhow::Error;
use anyhow::{anyhow, bail};
use base64;
use bcs;
use fastcrypto::traits::EncodeDecodeBase64;
use mockall::{automock, predicate::*};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use shared_crypto::intent::Intent;
use std::collections::{BTreeMap, HashSet};
use std::process::Command;
// use std::process::Command;
use sui_types::base_types::SuiAddress;
use sui_types::crypto::{PublicKey, Signature, SuiKeyPair};

#[derive(Serialize, Deserialize)]
pub struct External {
    /// active external binary signer
    pub signer: String,
    /// alias to address mapping
    pub aliases: BTreeMap<SuiAddress, Alias>,
    // address to (pubkey, signer, key_id)
    pub keys: BTreeMap<SuiAddress, (PublicKey, String, String)>,
    #[serde(skip_deserializing)]
    #[serde(skip_serializing)]
    #[serde(default = "default_runner")]
    command_runner: Box<dyn CommandRunner>,
}

#[automock]
pub trait CommandRunner: Send + Sync {
    fn run(&self, command: &str, args: Vec<String>) -> Result<JsonValue, Error>;
}

fn default_runner() -> Box<dyn CommandRunner> {
    Box::new(StdCommandRunner {})
}

struct StdCommandRunner;

use jsonrpc::client_sync::Endpoint;

#[derive(Serialize, Deserialize, Debug)]
struct Response {
    id: String,
    result: JsonValue,
}

impl CommandRunner for StdCommandRunner {
    fn run(&self, command: &str, args: Vec<String>) -> Result<JsonValue, Error> {
        // spawn tokio
        let mut cmd = Command::new(command).spawn().unwrap();

        // spawn tokio process
        let mut endpoint = Endpoint::new(
            cmd.stdout.take().expect("No stdout"),
            cmd.stdin.take().expect("no stdin"),
        );

        let res: Response = endpoint.call("run", args.clone())?;
        if res.id != "run" {
            return Err(anyhow!("Unexpected response id: {}", res.id));
        }
        if res.result.is_null() {
            return Err(anyhow!("Command returned null result"));
        }

        let output = cmd
            .wait_with_output()
            .map_err(|e| anyhow!("Failed to wait for command to finish: {}", e))?;

        if !output.status.success() {
            println!("output: {:?}", output);
            return Err(Error::msg(format!(
                "Command failed with status: {}",
                output.status
            )));
        }

        // TODO?
        let result = res.result;
        println!("result: {:?}", result);

        if result["error"].is_string() {
            return Err(anyhow!(
                "Command failed with error: {}",
                result["error"].as_str().unwrap()
            ));
        }

        Ok(result)
    }
}

impl External {
    pub fn new(signer: String) -> Self {
        Self {
            signer,
            aliases: Default::default(),
            keys: Default::default(),
            command_runner: Box::new(StdCommandRunner),
        }
    }

    pub fn from_existing(old: &mut Self) -> Self {
        Self {
            signer: old.signer.clone(),
            aliases: old.aliases.clone(),
            keys: old.keys.clone(),
            command_runner: Box::new(StdCommandRunner),
        }
    }

    pub fn new_for_test(command_runner: Box<dyn CommandRunner>) -> Self {
        Self {
            signer: "sui-key-tool".to_string(),
            aliases: Default::default(),
            keys: Default::default(),
            command_runner,
        }
    }

    pub fn exec(&self, command: &str, args: Vec<String>) -> Result<JsonValue, Error> {
        self.command_runner.run(command, args)
    }

    pub fn keys(&self) -> Vec<String> {
        let result = self
            .exec(&self.signer, vec!["--list-keys".to_string()])
            .unwrap();
        println!("result: {:?}", result);

        // array of strings
        let keys = result["keys"]
            .as_array()
            .ok_or_else(|| anyhow!("Failed to parse keys"))
            .unwrap();

        let mut key_ids = Vec::new();
        for key in keys {
            let key_id = key["key"]
                .as_str()
                .ok_or_else(|| anyhow!("Failed to parse key id"))
                .unwrap();
            key_ids.push(key_id.to_string());
        }
        key_ids
    }
}

impl AccountKeystore for External {
    fn add_key(&mut self, _alias: Option<String>, _keypair: SuiKeyPair) -> Result<(), Error> {
        Err(anyhow!("Not supported for external keys."))
    }

    fn create_key(&mut self, _alias: Option<String>) -> Result<SuiAddress, Error> {
        // TODO errors
        let res = self.exec(&self.signer, vec!["--create-key".to_string()])?;
        println!("result: {:?}", res);

        // key_id is the unique identifier for the key for the given signer
        let key_id = res["key_id"]
            .as_str()
            .ok_or_else(|| anyhow!("Failed to parse address"))?;
        let public_key = res["public_key"]
            .as_str()
            .ok_or_else(|| anyhow!("Failed to parse public key"))?;
        println!("public {}", public_key);
        let public_key = PublicKey::decode_base64(public_key)
            .map_err(|e| anyhow!("Failed to decode public key: {}", e))?;
        let address: SuiAddress = (&public_key).into();

        self.keys.insert(
            address,
            (public_key, self.signer.clone(), key_id.to_string()),
        );
        Ok(address)
    }

    fn remove_key(&mut self, _address: SuiAddress) -> Result<(), Error> {
        Err(anyhow!("Not supported for external keys."))
    }

    fn keys(&self) -> Vec<PublicKey> {
        let mut keys = Vec::new();
        for (_, (public, _, _)) in &self.keys {
            keys.push(public.clone());
        }
        keys
    }

    fn get_key(&self, _address: &SuiAddress) -> Result<&SuiKeyPair, Error> {
        Err(anyhow!("Not supported for external keys."))
    }

    fn sign_hashed(&self, address: &SuiAddress, msg: &[u8]) -> Result<Signature, signature::Error> {
        // TODO this should verify that the key id matches the address

        let key_id = self
            .keys
            .get(address)
            .ok_or_else(|| signature::Error::from_source(anyhow!("Key not found")))?
            .2
            .clone();

        let result = self
            .exec(
                &self.signer,
                vec![
                    "sign-hashed".to_string(),
                    "--key-id".to_string(),
                    key_id.to_string(),
                    "--msg".to_string(),
                    #[allow(deprecated)]
                    base64::encode(msg),
                ],
            )
            .map_err(|e| signature::Error::from_source(e))?;

        let signature = result["signature"]
            .as_str()
            .ok_or_else(|| signature::Error::from_source(anyhow!("Failed to parse signature")))?;

        let signature = Signature::decode_base64(signature).map_err(|e| {
            signature::Error::from_source(anyhow!("Failed to decode signature: {}", e))
        })?;
        Ok(signature)
    }

    fn sign_secure<T>(
        &self,
        address: &SuiAddress,
        msg: &T,
        intent: Intent,
    ) -> Result<Signature, signature::Error>
    where
        T: Serialize,
    {
        // TODO this should verify that the key id matches the address

        let key_id = self
            .keys
            .get(address)
            .ok_or_else(|| signature::Error::from_source(anyhow!("Key not found")))?
            .2
            .clone();

        println!("SIGN FOR {} = {}", key_id, address);
        let result = self
            .exec(
                &self.signer,
                vec![
                    "--sign".to_string(),
                    "--key-id".to_string(),
                    key_id.to_string(),
                    "--msg".to_string(),
                    #[allow(deprecated)]
                    base64::encode(bcs::to_bytes(msg).unwrap()),
                    "--intent".to_string(),
                    #[allow(deprecated)]
                    base64::encode(serde_json::to_vec(&intent).unwrap()),
                ],
            )
            .map_err(|e| signature::Error::from_source(anyhow!("Failed to sign message: {}", e)))?;

        let signature = result["signature"]
            .as_str()
            .ok_or_else(|| signature::Error::from_source(anyhow!("Failed to parse signature")))?;

        let signature = Signature::decode_base64(signature).unwrap();
        Ok(signature)
    }

    fn addresses_with_alias(&self) -> Vec<(&SuiAddress, &Alias)> {
        let mut addresses = Vec::new();
        for (address, alias) in &self.aliases {
            addresses.push((address, alias));
        }
        addresses
    }

    fn aliases(&self) -> Vec<&Alias> {
        let mut aliases = Vec::new();
        for alias in self.aliases.values() {
            aliases.push(alias);
        }
        aliases
    }

    fn aliases_mut(&mut self) -> Vec<&mut Alias> {
        let mut aliases = Vec::new();
        for alias in self.aliases.values_mut() {
            aliases.push(alias);
        }
        aliases
    }

    fn get_alias_by_address(&self, address: &SuiAddress) -> Result<String, Error> {
        match self.aliases.get(address) {
            Some(alias) => Ok(alias.alias.clone()),
            None => bail!("Cannot find alias for address {address}"),
        }
    }

    fn get_address_by_alias(&self, alias: String) -> Result<&SuiAddress, Error> {
        self.addresses_with_alias()
            .iter()
            .find(|x| x.1.alias == alias)
            .ok_or_else(|| anyhow!("Cannot resolve alias {alias} to an address"))
            .map(|x| x.0)
    }

    fn create_alias(&self, alias: Option<String>) -> Result<String, Error> {
        match alias {
            Some(a) if self.alias_exists(&a) => {
                bail!("Alias {a} already exists. Please choose another alias.")
            }
            Some(a) => crate::keystore::validate_alias(&a),
            None => Ok(random_name(
                &self
                    .alias_names()
                    .into_iter()
                    .map(|x| x.to_string())
                    .collect::<HashSet<_>>(),
            )),
        }
    }

    fn update_alias(&mut self, old_alias: &str, new_alias: Option<&str>) -> Result<String, Error> {
        if !self.alias_exists(old_alias) {
            bail!("The provided alias {old_alias} does not exist");
        }
        let new_alias_name = self.create_alias(new_alias.map(str::to_string))?;
        for a in self.aliases_mut() {
            if a.alias == old_alias {
                let pk = &a.public_key_base64;
                *a = Alias {
                    alias: new_alias_name.clone(),
                    public_key_base64: pk.clone(),
                };
            }
        }
        Ok(new_alias_name)
    }
}

#[allow(unused_imports)]
mod tests {
    use super::{External, MockCommandRunner};
    use crate::keystore::{AccountKeystore, Keystore};
    use fastcrypto::traits::EncodeDecodeBase64;
    use mockall::predicate::eq;
    use serde_json::Value as JsonValue;
    use sui_types::crypto::{PublicKey, SuiKeyPair};

    #[test]
    fn test_external_signer() {
        let mut mock = MockCommandRunner::new();
        mock.expect_run()
            .with(
                eq("sui-key-tool"),
                eq(vec!["--key".to_string(), "test_key".to_string()]),
            )
            .times(1)
            .returning(|_, _| Ok(JsonValue::Null));
        let external = External::new_for_test(Box::new(mock));
        let args = vec!["--key".to_string(), "test_key".to_string()];
        assert!(external.exec("sui-key-tool", args).is_ok());

        let mut keystore = Keystore::External(external);

        let kp = SuiKeyPair::decode_base64("APCWxPNCbgGxOYKeMfPqPmXmwdNVyau9y4IsyBcmC14A").unwrap();
        keystore.add_key(None, kp).unwrap_err();
    }
    // happy path
    // add a key

    // remove a key

    // list keys

    // get key by address

    // get key by alias

    // swap out a device

    // api key no longer exists / valid

    // no more slots
}
