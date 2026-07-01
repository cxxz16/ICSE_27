
from .fig_builder import build_fig, FIG
from .narrow import narrow
from .discriminator_classifier import (
    classify as classify_discriminator,
    DiscriminatorOrigin,
    DiscriminatorOriginInfo,
)
from .context_extractor import (
    build_context, DispatchContext, Reachability, CandidateCallee,
)
from .llm_resolver import resolve, build_prompt, ResolutionResult, make_anthropic_backend
from .entry_finder import (
    discover_entry, EntryDiscovery, EntryHop, CallGraph,
)
from .superglobal_keys import superglobal_keys_reaching_line, strong_target_values_at

__all__ = [
    "build_fig", "FIG", "narrow",
    "classify_discriminator", "DiscriminatorOrigin", "DiscriminatorOriginInfo",
    "build_context", "DispatchContext", "Reachability", "CandidateCallee",
    "resolve", "build_prompt", "ResolutionResult",
    "make_anthropic_backend",
    "discover_entry", "EntryDiscovery", "EntryHop", "CallGraph",
    "superglobal_keys_reaching_line",
    "strong_target_values_at",
]
