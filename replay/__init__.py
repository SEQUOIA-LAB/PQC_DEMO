"""Phase 3: stepped replay engine.

The handshake completes in milliseconds — too fast to watch live (PROJECT_PLAN.md
§4.5). This is CAPTURE-THEN-REPLAY: take the real artifacts recorded by capture/
and app/, order them into a human-paced timeline with pause/step semantics. We do
NOT animate a live handshake; we replay genuine recorded events.
"""
