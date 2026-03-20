pub mod backend;
pub mod config;
pub mod errors;
pub mod traits;
pub mod types;

pub use backend::OllamaBackend;
pub use config::Config;
pub use errors::LlmError;
pub use traits::LlmBackend;
pub use types::{
    ArtifactBundle, ArtifactContent, ArtifactFile,
    ChatMessage, Digest, LlmVote, PullContext, ScanDecision,
};
