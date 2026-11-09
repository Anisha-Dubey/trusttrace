"""Community report lifecycle state machine."""

from typing import Set, Tuple
from ..domain.enums import VerificationState


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal verification state transition is attempted."""
    pass


# Explicit set of permitted (from_state, to_state) transitions
ALLOWED_TRANSITIONS: Set[Tuple[VerificationState, VerificationState]] = {
    (VerificationState.UNVERIFIED, VerificationState.CORROBORATED),
    (VerificationState.UNVERIFIED, VerificationState.DISPUTED),
    (VerificationState.UNVERIFIED, VerificationState.REVIEWED),
    (VerificationState.CORROBORATED, VerificationState.DISPUTED),
    (VerificationState.DISPUTED, VerificationState.REVIEWED),
}


def validate_transition(
    current_state: VerificationState,
    target_state: VerificationState,
) -> bool:
    """Validate whether transitioning from current_state to target_state is permitted.
    
    Raises:
        InvalidStateTransitionError: If the transition is prohibited.
    """
    if current_state == target_state:
        return True  # Idempotent no-op

    transition = (current_state, target_state)
    if transition not in ALLOWED_TRANSITIONS:
        raise InvalidStateTransitionError(
            f"Invalid state transition: '{current_state.value}' -> '{target_state.value}'. "
            f"Permitted transitions are: {[f'{s[0].value} -> {s[1].value}' for s in ALLOWED_TRANSITIONS]}"
        )
    return True
