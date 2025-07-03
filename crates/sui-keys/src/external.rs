use crate::keystore::{AccountKeystore, Alias};
use crate::random_names::random_name;
use anyhow::Error;
use anyhow::{anyhow, bail};
use base64;
use bcs;
use fastcrypto::traits::EncodeDecodeBase64;
use jsonrpc::client_sync::Endpoint;
use mockall::{automock, predicate::*};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{json, Value as JsonValue};
use shared_crypto::intent::Intent;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::process::{Command, Stdio};
// use std::process::Command;
use sui_types::base_types::SuiAddress;
use sui_types::crypto::{PublicKey, Signature, SuiKeyPair};

pub struct External {
    /// alias to address mapping
    pub aliases: BTreeMap<SuiAddress, Alias>,
    // address to (pubkey, signer, key_id)
    pub keys: BTreeMap<SuiAddress, Key>,
    command_runner: Box<dyn CommandRunner>,
    path: Option<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Key {
    pub public_key: PublicKey,
    pub signer: String,
    pub key_id: String,
}

#[automock]
pub trait CommandRunner: Send + Sync {
    fn run(&self, command: &str, method: &str, args: JsonValue) -> Result<JsonValue, Error>;
}
//
// fn default_runner() -> Box<dyn CommandRunner> {
//     Box::new(StdCommandRunner {})
// }

struct StdCommandRunner;
impl CommandRunner for StdCommandRunner {
    fn run(&self, command: &str, method: &str, args: JsonValue) -> Result<JsonValue, Error> {
        // spawn tokio
        let mut cmd = Command::new(command)
            .arg("call")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();

        // spawn tokio process
        let mut endpoint = Endpoint::new(
            cmd.stdout.take().expect("No stdout"),
            cmd.stdin.take().expect("No stdin"),
        );

        let res: JsonValue = endpoint.call(method, args)?;
        if res.is_null() {
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

        if !res["error"].is_null() {
            return Err(anyhow!("Command failed with error: {:?}", res["error"]));
        }

        Ok(res)
    }
}

impl External {
    pub fn new(path: &PathBuf) -> Result<Self, anyhow::Error> {
        let mut aliases_store_path = path.clone();
        aliases_store_path.set_extension("aliases");
        let aliases: BTreeMap<SuiAddress, Alias> = if aliases_store_path.exists() {
            let aliases_store: String = std::fs::read_to_string(&aliases_store_path)
                .map_err(|e| anyhow!("Failed to read aliases file: {}", e))?;
            serde_json::from_str(&aliases_store)
                .map_err(|e| anyhow!("Failed to parse aliases file: {}", e))?
        } else {
            Default::default()
        };

        let mut keys_store_path = path.clone();
        keys_store_path.set_extension("keys");
        let keys: BTreeMap<SuiAddress, Key> = if keys_store_path.exists() {
            let keys_store: String = std::fs::read_to_string(&keys_store_path)
                .map_err(|e| anyhow!("Failed to read keys file: {}", e))?;
            serde_json::from_str(&keys_store)
                .map_err(|e| anyhow!("Failed to parse keys file: {}", e))?
        } else {
            Default::default()
        };

        Ok(Self {
            aliases,
            keys,
            command_runner: Box::new(StdCommandRunner),
            path: Some(path.clone()),
        })
    }

    pub fn from_existing(old: &mut Self) -> Self {
        Self {
            aliases: old.aliases.clone(),
            keys: old.keys.clone(),
            command_runner: Box::new(StdCommandRunner),
            path: old.path.clone(),
        }
    }

    pub fn new_for_test(command_runner: Box<dyn CommandRunner>) -> Self {
        Self {
            aliases: Default::default(),
            keys: Default::default(),
            command_runner,
            path: None,
        }
    }

    pub fn exec(&self, command: &str, method: &str, args: JsonValue) -> Result<JsonValue, Error> {
        self.command_runner.run(command, method, args)
    }

    pub fn add_existing(&mut self, signer: String, key_id: String) -> Result<(), Error> {
        let keys = self.keys(signer.clone()).unwrap();

        let key: Key = keys
            .into_iter()
            .find(|k| k.key_id == key_id)
            .ok_or_else(|| anyhow!("Key with id {} not found for signer {}", key_id, signer))?;

        self.keys.insert(
            (&key.public_key).into(),
            Key {
                public_key: key.public_key,
                signer,
                key_id,
            },
        );
        Ok(())
    }

    pub fn keys(&self, signer: String) -> Result<Vec<Key>, Error> {
        let result = self.exec(&signer, "keys", json![null]).unwrap();
        println!("result: {:?}", result);

        // array of strings
        let keys_json = result["keys"]
            .as_array()
            .ok_or_else(|| anyhow!("Failed to parse keys"))
            .unwrap();

        let mut keys = Vec::new();
        for key_json in keys_json {
            let key_id = key_json["key"]
                .as_str()
                .ok_or_else(|| anyhow!("Failed to parse key id"))
                .unwrap();
            keys.push(Key {
                public_key: PublicKey::decode_base64(key_json["public_key"].as_str().unwrap())
                    .map_err(|e| anyhow!("Failed to decode public key: {}", e))?,
                signer: signer.clone(),
                key_id: key_id.to_string(),
            });
        }
        Ok(keys)
    }

    pub fn save_aliases(&self) -> Result<(), Error> {
        if let Some(path) = &self.path {
            let aliases_store: String = serde_json::to_string_pretty(&self.aliases)
                .map_err(|e| anyhow!("Serialization error: {}", e))?;

            let mut path = path.clone();
            path.set_extension("aliases");
            std::fs::write(path, aliases_store)
                .map_err(|e| anyhow!("Failed to write to file: {}", e))?;
            Ok(())
        } else {
            Err(anyhow!("Path is not set for External keystore"))
        }
    }

    pub fn save_keys(&self) -> Result<(), Error> {
        if let Some(path) = &self.path {
            let keys_store: String = serde_json::to_string_pretty(&self.keys)
                .map_err(|e| anyhow!("Serialization error: {}", e))?;

            let mut path = path.clone();
            path.set_extension("keys");
            std::fs::write(path, keys_store)
                .map_err(|e| anyhow!("Failed to write to file: {}", e))?;
            Ok(())
        } else {
            Err(anyhow!("Path is not set for External keystore"))
        }
    }

    pub fn save(&self) -> Result<(), Error> {
        self.save_aliases()?;
        self.save_keys()?;
        Ok(())
    }
}

impl Serialize for External {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(
            self.path
                .as_ref()
                .unwrap_or(&PathBuf::default())
                .to_str()
                .unwrap_or(""),
        )
    }
}

impl<'de> Deserialize<'de> for External {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        External::new(&PathBuf::from(String::deserialize(deserializer)?)).map_err(D::Error::custom)
    }
}

impl AccountKeystore for External {
    fn add_key(&mut self, _alias: Option<String>, _keypair: SuiKeyPair) -> Result<(), Error> {
        Err(anyhow!("Not supported for external keys."))
    }

    fn create_key(&mut self, _alias: Option<String>, signer: String) -> Result<SuiAddress, Error> {
        let res = self.exec(&signer, "create_key", json![null])?;

        // key_id is the unique identifier for the key for the given signer
        let key_id = res["key_id"]
            .as_str()
            .ok_or_else(|| anyhow!("Failed to parse address"))?;
        let public_key = res["public_key"]
            .as_str()
            .ok_or_else(|| anyhow!("Failed to parse public key"))?;
        let public_key = PublicKey::decode_base64(public_key)
            .map_err(|e| anyhow!("Failed to decode public key: {}", e))?;
        let address: SuiAddress = (&public_key).into();

        self.keys.insert(
            address,
            Key {
                public_key,
                signer: signer.clone(),
                key_id: key_id.to_string(),
            },
        );
        Ok(address)
    }

    fn remove_key(&mut self, _address: SuiAddress) -> Result<(), Error> {
        Err(anyhow!("Not supported for external keys."))
    }

    fn keys(&self) -> Vec<PublicKey> {
        let mut keys = Vec::new();
        for (_, Key { public_key, .. }) in &self.keys {
            keys.push(public_key.clone());
        }
        keys
    }

    fn get_key(&self, _address: &SuiAddress) -> Result<&SuiKeyPair, Error> {
        Err(anyhow!("Not supported for external keys."))
    }

    fn sign_hashed(&self, address: &SuiAddress, msg: &[u8]) -> Result<Signature, signature::Error> {
        // TODO this should verify that the key id matches the address

        println!("KEYS: {:?}", self.keys);
        let Key { key_id, signer, .. } = self
            .keys
            .get(address)
            .ok_or_else(|| signature::Error::from_source(anyhow!("Key not found")))?
            .clone();

        let result = self
            .exec(
                &signer,
                "sign_hashed",
                json![{"keyId": key_id, "msg": base64::encode(msg)}],
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

        println!("KEYS: {:?}", self.keys);
        let Key { key_id, signer, .. } = self
            .keys
            .get(address)
            .ok_or_else(|| signature::Error::from_source(anyhow!("Key not found")))?
            .clone();

        let result = self
            .exec(
                &signer,
                "sign",
                json![{
                    "key_id": key_id,
                    "msg": base64::encode(bcs::to_bytes(msg).unwrap()),
                    "intent": serde_json::to_value(&intent).unwrap()
                }],
            )
            .map_err(|e| signature::Error::from_source(anyhow!("Failed to sign message: {}", e)))?;

        let result = result
            .as_object()
            .ok_or_else(|| signature::Error::from_source(anyhow!("Failed to parse result")))?;

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
