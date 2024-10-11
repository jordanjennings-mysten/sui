// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[path = "unit_tests/upgrade_compatibility_tests.rs"]
#[cfg(test)]
mod upgrade_compatibility_tests;

use std::collections::hash_map::Entry::{Occupied, Vacant};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{stdout, IsTerminal};

use anyhow::{anyhow, Context, Error};
use codespan_reporting::diagnostic::{Diagnostic, Label};
use codespan_reporting::files::SimpleFiles;
use codespan_reporting::term;

use move_binary_format::file_format::{FunctionDefinitionIndex, TableIndex};
use move_binary_format::{
    compatibility::Compatibility,
    compatibility_mode::CompatibilityMode,
    file_format::Visibility,
    normalized::{Enum, Function, Module, Struct},
    CompiledModule,
};
use move_core_types::{
    account_address::AccountAddress,
    identifier::{IdentStr, Identifier},
};
use move_package::compilation::compiled_package::CompiledUnitWithSource;
use sui_json_rpc_types::{SuiObjectDataOptions, SuiRawData};
use sui_move_build::CompiledPackage;
use sui_protocol_config::ProtocolConfig;
use sui_sdk::SuiClient;
use sui_types::{base_types::ObjectID, execution_config_utils::to_binary_config};

/// Errors that can occur during upgrade compatibility checks.
/// one-to-one related to the underlying trait functions see: [`CompatibilityMode`]
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum UpgradeCompatibilityModeError {
    ModuleMissing {
        name: Identifier,
    },
    StructMissing {
        name: Identifier,
        old_struct: Struct,
    },
    StructAbilityMismatch {
        name: Identifier,
        old_struct: Struct,
        new_struct: Struct,
    },
    StructTypeParamMismatch {
        name: Identifier,
        old_struct: Struct,
        new_struct: Struct,
    },
    StructFieldMismatch {
        name: Identifier,
        old_struct: Struct,
        new_struct: Struct,
    },
    EnumMissing {
        name: Identifier,
        old_enum: Enum,
    },
    EnumAbilityMismatch {
        name: Identifier,
        old_enum: Enum,
        new_enum: Enum,
    },
    EnumTypeParamMismatch {
        name: Identifier,
        old_enum: Enum,
        new_enum: Enum,
    },
    EnumNewVariant {
        name: Identifier,
        old_enum: Enum,
        new_enum: Enum,
    },
    EnumVariantMissing {
        name: Identifier,
        old_enum: Enum,
        tag: usize,
    },
    EnumVariantMismatch {
        name: Identifier,
        old_enum: Enum,
        new_enum: Enum,
        tag: usize,
    },
    FunctionMissingPublic {
        name: Identifier,
        old_function: Function,
    },
    FunctionMissingEntry {
        name: Identifier,
        old_function: Function,
    },
    FunctionSignatureMismatch {
        name: Identifier,
        old_function: Function,
        new_function: Function,
    },
    FunctionLostPublicVisibility {
        name: Identifier,
        old_function: Function,
    },
    FunctionEntryCompatibility {
        name: Identifier,
        old_function: Function,
        new_function: Function,
    },
}

impl UpgradeCompatibilityModeError {
    /// check if the error breaks compatibility for a given [`Compatibility`]
    fn breaks_compatibility(&self, compatability: &Compatibility) -> bool {
        match self {
            UpgradeCompatibilityModeError::ModuleMissing { .. } => true,

            UpgradeCompatibilityModeError::StructAbilityMismatch { .. }
            | UpgradeCompatibilityModeError::StructTypeParamMismatch { .. }
            | UpgradeCompatibilityModeError::EnumAbilityMismatch { .. }
            | UpgradeCompatibilityModeError::EnumTypeParamMismatch { .. }
            | UpgradeCompatibilityModeError::FunctionMissingPublic { .. }
            | UpgradeCompatibilityModeError::FunctionLostPublicVisibility { .. } => true,

            UpgradeCompatibilityModeError::StructFieldMismatch { .. }
            | UpgradeCompatibilityModeError::EnumVariantMissing { .. }
            | UpgradeCompatibilityModeError::EnumVariantMismatch { .. } => {
                compatability.check_datatype_layout
            }

            UpgradeCompatibilityModeError::StructMissing { .. }
            | UpgradeCompatibilityModeError::EnumMissing { .. } => true,

            UpgradeCompatibilityModeError::FunctionSignatureMismatch { old_function, .. } => {
                if old_function.visibility == Visibility::Public {
                    return true;
                }
                if old_function.is_entry {
                    compatability.check_private_entry_linking
                } else {
                    false
                }
            }

            UpgradeCompatibilityModeError::FunctionMissingEntry { .. }
            | UpgradeCompatibilityModeError::FunctionEntryCompatibility { .. } => {
                compatability.check_private_entry_linking
            }
            UpgradeCompatibilityModeError::EnumNewVariant { .. } => {
                compatability.check_datatype_layout
            }
        }
    }
}

/// A compatibility mode that collects errors as a vector of enums which describe the error causes
#[derive(Default)]
pub(crate) struct CliCompatibilityMode {
    errors: Vec<UpgradeCompatibilityModeError>,
}

impl CompatibilityMode for CliCompatibilityMode {
    type Error = Vec<UpgradeCompatibilityModeError>;
    // ignored, address is not populated pre-tx
    fn module_id_mismatch(
        &mut self,
        _old_addr: &AccountAddress,
        _old_name: &IdentStr,
        _new_addr: &AccountAddress,
        _new_name: &IdentStr,
    ) {
    }

    fn struct_missing(&mut self, name: &Identifier, old_struct: &Struct) {
        self.errors
            .push(UpgradeCompatibilityModeError::StructMissing {
                name: name.clone(),
                old_struct: old_struct.clone(),
            });
    }

    fn struct_ability_mismatch(
        &mut self,
        name: &Identifier,
        old_struct: &Struct,
        new_struct: &Struct,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::StructAbilityMismatch {
                name: name.clone(),
                old_struct: old_struct.clone(),
                new_struct: new_struct.clone(),
            });
    }

    fn struct_type_param_mismatch(
        &mut self,
        name: &Identifier,
        old_struct: &Struct,
        new_struct: &Struct,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::StructTypeParamMismatch {
                name: name.clone(),
                old_struct: old_struct.clone(),
                new_struct: new_struct.clone(),
            });
    }

    fn struct_field_mismatch(
        &mut self,
        name: &Identifier,
        old_struct: &Struct,
        new_struct: &Struct,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::StructFieldMismatch {
                name: name.clone(),
                old_struct: old_struct.clone(),
                new_struct: new_struct.clone(),
            });
    }

    fn enum_missing(&mut self, name: &Identifier, old_enum: &Enum) {
        self.errors
            .push(UpgradeCompatibilityModeError::EnumMissing {
                name: name.clone(),
                old_enum: old_enum.clone(),
            });
    }

    fn enum_ability_mismatch(&mut self, name: &Identifier, old_enum: &Enum, new_enum: &Enum) {
        self.errors
            .push(UpgradeCompatibilityModeError::EnumAbilityMismatch {
                name: name.clone(),
                old_enum: old_enum.clone(),
                new_enum: new_enum.clone(),
            });
    }

    fn enum_type_param_mismatch(&mut self, name: &Identifier, old_enum: &Enum, new_enum: &Enum) {
        self.errors
            .push(UpgradeCompatibilityModeError::EnumTypeParamMismatch {
                name: name.clone(),
                old_enum: old_enum.clone(),
                new_enum: new_enum.clone(),
            });
    }

    fn enum_new_variant(&mut self, name: &Identifier, old_enum: &Enum, new_enum: &Enum) {
        self.errors
            .push(UpgradeCompatibilityModeError::EnumNewVariant {
                name: name.clone(),
                old_enum: old_enum.clone(),
                new_enum: new_enum.clone(),
            });
    }

    fn enum_variant_missing(&mut self, name: &Identifier, old_enum: &Enum, tag: usize) {
        self.errors
            .push(UpgradeCompatibilityModeError::EnumVariantMissing {
                name: name.clone(),
                old_enum: old_enum.clone(),
                tag,
            });
    }

    fn enum_variant_mismatch(
        &mut self,
        name: &Identifier,
        old_enum: &Enum,
        new_enum: &Enum,
        variant_idx: usize,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::EnumVariantMismatch {
                name: name.clone(),
                old_enum: old_enum.clone(),
                new_enum: new_enum.clone(),
                tag: variant_idx,
            });
    }

    fn function_missing_public(&mut self, name: &Identifier, old_function: &Function) {
        self.errors
            .push(UpgradeCompatibilityModeError::FunctionMissingPublic {
                name: name.clone(),
                old_function: old_function.clone(),
            });
    }

    fn function_missing_entry(&mut self, name: &Identifier, old_function: &Function) {
        self.errors
            .push(UpgradeCompatibilityModeError::FunctionMissingEntry {
                name: name.clone(),
                old_function: old_function.clone(),
            });
    }

    fn function_signature_mismatch(
        &mut self,
        name: &Identifier,
        old_function: &Function,
        new_function: &Function,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::FunctionSignatureMismatch {
                name: name.clone(),
                old_function: old_function.clone(),
                new_function: new_function.clone(),
            });
    }

    fn function_lost_public_visibility(&mut self, name: &Identifier, old_function: &Function) {
        self.errors.push(
            UpgradeCompatibilityModeError::FunctionLostPublicVisibility {
                name: name.clone(),
                old_function: old_function.clone(),
            },
        );
    }

    fn function_entry_compatibility(
        &mut self,
        name: &Identifier,
        old_function: &Function,
        new_function: &Function,
    ) {
        self.errors
            .push(UpgradeCompatibilityModeError::FunctionEntryCompatibility {
                name: name.clone(),
                old_function: old_function.clone(),
                new_function: new_function.clone(),
            });
    }

    fn finish(self, compatability: &Compatibility) -> Result<(), Self::Error> {
        let errors: Vec<UpgradeCompatibilityModeError> = self
            .errors
            .into_iter()
            .filter(|e| e.breaks_compatibility(compatability))
            .collect();

        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(())
    }
}

#[allow(dead_code)]
struct IdentifierTableLookup {
    struct_identifier_to_index: BTreeMap<Identifier, TableIndex>,
    enum_identifier_to_index: BTreeMap<Identifier, TableIndex>,
    function_identifier_to_index: BTreeMap<Identifier, TableIndex>,
}

fn table_index(compiled_module: &CompiledModule) -> IdentifierTableLookup {
    // for each in compiled module
    let struct_identifier_to_index: BTreeMap<Identifier, TableIndex> = compiled_module
        .struct_defs()
        .iter()
        .enumerate()
        .map(|(i, d)| {
            // get the identifier of the struct
            let s_id = compiled_module
                .identifier_at(compiled_module.datatype_handle_at(d.struct_handle).name);
            (s_id.to_owned(), i as TableIndex)
        })
        .collect();

    let enum_identifier_to_index: BTreeMap<Identifier, TableIndex> = compiled_module
        .enum_defs()
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let e_id = compiled_module
                .identifier_at(compiled_module.datatype_handle_at(d.enum_handle).name);
            (e_id.to_owned(), i as TableIndex)
        })
        .collect();

    let function_identifier_to_index: BTreeMap<Identifier, TableIndex> = compiled_module
        .function_defs()
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let f_id =
                compiled_module.identifier_at(compiled_module.function_handle_at(d.function).name);
            (f_id.to_owned(), i as TableIndex)
        })
        .collect();

    IdentifierTableLookup {
        struct_identifier_to_index,
        enum_identifier_to_index,
        function_identifier_to_index,
    }
}

/// Check the upgrade compatibility of a new package with an existing on-chain package.
pub(crate) async fn check_compatibility(
    client: &SuiClient,
    package_id: ObjectID,
    new_package: CompiledPackage,
    protocol_config: ProtocolConfig,
) -> Result<(), Error> {
    let existing_obj_read = client
        .read_api()
        .get_object_with_options(package_id, SuiObjectDataOptions::new().with_bcs())
        .await
        .context("Unable to get existing package")?;

    let existing_obj = existing_obj_read
        .into_object()
        .context("Unable to get existing package")?
        .bcs
        .ok_or_else(|| anyhow!("Unable to read object"))?;

    let existing_package = match existing_obj {
        SuiRawData::Package(pkg) => Ok(pkg),
        SuiRawData::MoveObject(_) => Err(anyhow!("Object found when package expected")),
    }?;

    let existing_modules = existing_package
        .module_map
        .iter()
        .map(|m| CompiledModule::deserialize_with_config(m.1, &to_binary_config(&protocol_config)))
        .collect::<Result<Vec<_>, _>>()
        .context("Unable to get existing package")?;

    compare_packages(existing_modules, new_package)
}

/// Collect all the errors into a single error message.
fn compare_packages(
    existing_modules: Vec<CompiledModule>,
    new_package: CompiledPackage,
) -> Result<(), Error> {
    // create a map from the new modules
    let new_modules_map: HashMap<Identifier, CompiledModule> = new_package
        .get_modules()
        .map(|m| (m.self_id().name().to_owned(), m.clone()))
        .collect();

    let lookup: HashMap<Identifier, IdentifierTableLookup> = existing_modules
        .iter()
        .map(|m| (m.self_id().name().to_owned(), table_index(m)))
        .collect();

    let errors: Vec<(Identifier, UpgradeCompatibilityModeError)> = existing_modules
        .iter()
        .flat_map(|existing_module| {
            let name = existing_module.self_id().name().to_owned();

            // find the new module with the same name
            match new_modules_map.get(&name) {
                Some(new_module) => {
                    let compatible = Compatibility::upgrade_check()
                        .check_with_mode::<CliCompatibilityMode>(
                            &Module::new(existing_module),
                            &Module::new(new_module),
                        );
                    if let Err(errors) = compatible {
                        errors.into_iter().map(|e| (name.to_owned(), e)).collect()
                    } else {
                        vec![]
                    }
                }
                None => vec![(
                    name.clone(),
                    UpgradeCompatibilityModeError::ModuleMissing { name },
                )],
            }
        })
        .collect();

    if errors.is_empty() {
        return Ok(());
    }

    let mut files = SimpleFiles::new();
    let config = term::Config::default();
    let mut writer;
    if stdout().is_terminal() {
        writer = term::termcolor::Buffer::ansi();
    } else {
        writer = term::termcolor::Buffer::no_color();
    }
    let mut file_id_map = HashMap::new();

    for (name, err) in errors {
        let compiled_unit_with_source = new_package
            .package
            .get_module_by_name_from_root(name.as_str())
            .context("Unable to get module")?;

        let source_path = compiled_unit_with_source.source_path.as_path();
        let file_id = match file_id_map.entry(source_path) {
            Occupied(entry) => *entry.get(),
            Vacant(entry) => {
                let source = fs::read_to_string(&compiled_unit_with_source.source_path)
                    .context("Unable to read source file")?;
                *entry.insert(files.add(source_path.to_string_lossy(), source))
            }
        };

        for diag in diag_from_error(&err, compiled_unit_with_source, file_id, &lookup[&name])
            .iter()
            .flatten()
        {
            term::emit(&mut writer, &config, &files, diag).context("Unable to emit error")?;
        }
    }

    Err(anyhow!(
        "{}\nUpgrade failed, this package requires changes to be compatible with the existing package. It's upgrade policy is set to 'Compatible'.",
        String::from_utf8(writer.into_inner()).context("Unable to convert buffer to string")?
    ))
}

/// Convert an error to a diagnostic using the specific error type's function.
fn diag_from_error(
    error: &UpgradeCompatibilityModeError,
    compiled_unit_with_source: &CompiledUnitWithSource,
    file_id: usize,
    lookup: &IdentifierTableLookup,
) -> Result<Vec<Diagnostic<usize>>, Error> {
    match error {
        UpgradeCompatibilityModeError::StructMissing { name, .. } => {
            missing_definition_diag("struct", &name, compiled_unit_with_source, file_id)
        }
        UpgradeCompatibilityModeError::EnumMissing { name, .. } => {
            missing_definition_diag("enum", &name, compiled_unit_with_source, file_id)
        }
        UpgradeCompatibilityModeError::FunctionMissingPublic { name, .. } => {
            missing_definition_diag("public function", &name, compiled_unit_with_source, file_id)
        }
        UpgradeCompatibilityModeError::FunctionMissingEntry { name, .. } => {
            missing_definition_diag("entry function", &name, compiled_unit_with_source, file_id)
        }

        UpgradeCompatibilityModeError::FunctionSignatureMismatch {
            name,
            old_function,
            new_function,
        } => function_signature_mismatch_diag(
            &name,
            old_function,
            new_function,
            compiled_unit_with_source,
            file_id,
            lookup,
        ),
        _ => todo!("Implement diag_from_error for {:?}", error),
    }
}

/// Return a diagnostic for a missing definition.
fn missing_definition_diag(
    declaration_kind: &str,
    identifier_name: &Identifier,
    compiled_unit_with_source: &CompiledUnitWithSource,
    file_id: usize,
) -> Result<Vec<Diagnostic<usize>>, Error> {
    let module_name = compiled_unit_with_source.unit.name;

    let start = compiled_unit_with_source
        .unit
        .source_map
        .definition_location
        .start() as usize;

    let end = compiled_unit_with_source
        .unit
        .source_map
        .definition_location
        .end() as usize;

    Ok(vec![Diagnostic::error()
        .with_message(format!("{declaration_kind} is missing"))
        .with_labels(vec![Label::primary(file_id, start..end).with_message(
            format!(
                "Module '{module_name}' expected {declaration_kind} '{identifier_name}', but found none"
            ),
        )])
        .with_notes(vec![format!(
            "{declaration_kind}s are part of a module's public interface and cannot be removed or changed during an upgrade, add back the {declaration_kind} '{identifier_name}'."
        )])])
}

/// Return a diagnostic for a function signature mismatch.
/// start by checking the lengths of the parameters and returns and return a diagnostic if they are different
/// if the lengths are the same check each parameter piece wise and return a diagnostic for each mismatch
fn function_signature_mismatch_diag(
    function_name: &Identifier,
    old_function: &Function,
    new_function: &Function,
    compiled_unit_with_source: &CompiledUnitWithSource,
    file_id: usize,
    lookup: &IdentifierTableLookup,
) -> Result<Vec<Diagnostic<usize>>, Error> {
    let module_name = compiled_unit_with_source.unit.name;
    let old_func_index = lookup
        .function_identifier_to_index
        .get(function_name)
        .context("Unable to get function index")?;

    let new_func_sourcemap = compiled_unit_with_source
        .unit
        .source_map
        .get_function_source_map(FunctionDefinitionIndex::new(*old_func_index))
        .context("Unable to get function source map")?;

    let identifier_start = new_func_sourcemap.definition_location.start() as usize;
    let identifier_end = new_func_sourcemap.definition_location.end() as usize;

    let mut diags = vec![];

    // handle function arguments
    if old_function.parameters.len() != new_function.parameters.len() {
        diags.push(
            Diagnostic::error()
                .with_message("Function signature mismatch")
                .with_labels(vec![Label::primary(
                    file_id,
                    identifier_start..identifier_end,
                )
                .with_message(format!(
                    "Function '{function_name}' expected {} parameters, have {}",
                    old_function.parameters.len(),
                    new_function.parameters.len()
                ))])
                .with_notes(vec![format!(
                    "Functions are part of a module's public interface and cannot be changed during an upgrade, restore the original function's parameters for function '{function_name}', expected {} parameters.",
                    old_function.parameters.len()
                )]),
        );
    } else if old_function.parameters != new_function.parameters {
        for ((i, old_param), new_param) in old_function
            .parameters
            .iter()
            .enumerate()
            .zip(new_function.parameters.iter())
        {
            if old_param != new_param {
                let start = new_func_sourcemap
                    .parameters
                    .get(i)
                    .context("Unable to get parameter location")?
                    .1
                    .start() as usize;

                let end = new_func_sourcemap
                    .parameters
                    .get(i)
                    .context("Unable to get parameter location")?
                    .1
                    .end() as usize;

                diags.push(
                    Diagnostic::error()
                        .with_message("Function signature mismatch")
                        .with_labels(vec![Label::primary(file_id, start..end).with_message(
                            format!("Function '{function_name}' unexpected parameter {new_param} at position {i}, expected {old_param}"),
                        )])
                        .with_notes(vec![format!(
                            "Functions are part of a module's public interface and cannot be changed during an upgrade, restore the original function's parameters for function '{function_name}'."
                        )]),
                );
            }
        }
    }

    // handle return
    if old_function.return_.len() != new_function.return_.len() {
        diags.push(
            Diagnostic::error()
                .with_message("Function signature mismatch")
                .with_labels(vec![Label::primary(
                    file_id,
                    identifier_start..identifier_end,
                )
                .with_message(format!(
                    "Function '{function_name}' expected to have {} return type(s), have {}",
                    old_function.return_.len(),
                    new_function.return_.len()
                ))])
                .with_notes(vec![format!(
                    "Functions are part of a module's public interface and cannot be changed during an upgrade, restore the original function's return types for function '{function_name}'."
                )]),
        );
    } else if old_function.return_ != new_function.return_ {
        for ((i, old_return), new_return) in old_function
            .return_
            .iter()
            .enumerate()
            .zip(new_function.return_.iter())
        {
            let returns = new_func_sourcemap
                .returns
                .get(i)
                .context("Unable to get return location")?;
            let start = returns.start() as usize;
            let end = returns.end() as usize;

            if old_return != new_return {
                diags.push(
                    Diagnostic::error()
                        .with_message("Function signature mismatch")
                        .with_labels(vec![Label::primary(
                            file_id,
                            start..end
                        )
                        .with_message(
                            if new_function.return_.len() == 1 {
                                format!("Module '{module_name}' function '{function_name}' has an unexpected return type {new_return}, expected {old_return}")
                            } else {
                                format!("Module '{module_name}' function '{function_name}' unexpected return type {new_return} at position {i}, expected {old_return}")
                            },
                        )])
                        .with_notes(vec![format!(
                            "Functions are part of a module's public interface and cannot be changed during an upgrade, restore the original function's return types for function '{function_name}'."
                        )]),
                );
            }
        }
    }

    Ok(diags)
}
