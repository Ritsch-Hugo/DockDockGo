pub mod backend;
pub mod config;
pub mod errors;
pub mod traits;
pub mod types;

pub use backend::{ModelInfo, OpenAiBackend};
pub use config::Config;
pub use errors::LlmError;
pub use traits::LlmBackend;
pub use types::{
    Alternative, ArbiterAnalysis, ArtifactBundle, ArtifactContent, ArtifactFile,
    ChatMessage, DecisionArbiterMeta, DecisionMetadata, DecisionWorkerMeta,
    Digest, FinalReport, LlmResponse, LlmVote, PullContext,
    ScanAnalysis, ScanDecision, ScanReasoning, ScanResult,
    ToolCall, Verdict, WorkerAnalysis,
};
