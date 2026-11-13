pub mod claude;
pub mod codex;
pub mod cursor;
pub mod generic_json;
pub mod generic_jsonl;
pub(crate) mod jsonl_common;
pub mod registry;
pub mod traits;

pub use registry::AdapterRegistry;
pub use traits::SourceAdapter;
