"""porter.emitters package"""
from porter.emitters.aider import AiderEmitter
from porter.emitters.claude import ClaudeEmitter
from porter.emitters.common import EmitterConflictError
from porter.emitters.cursor import CursorEmitter
from porter.emitters.generic import GenericEmitter
from porter.emitters.universal import UniversalEmitter

EMITTERS = {
    "claude": ClaudeEmitter,
    "cursor": CursorEmitter,
    "universal": UniversalEmitter,
    "aider": AiderEmitter,
    "generic": GenericEmitter,
}

__all__ = ["ClaudeEmitter", "CursorEmitter", "UniversalEmitter", "AiderEmitter", "GenericEmitter", "EMITTERS", "EmitterConflictError"]
