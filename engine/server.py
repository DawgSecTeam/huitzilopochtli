"""HTTP endpoints. See architecture.md §11.1. PHASE 2 (integration).

Wires engine.enrollment.handle_enroll / engine.checkin.handle_checkin /
engine.leaderboard.get_leaderboard behind stdlib http.server (or a thin WSGI
server) with a thread pool. Keep handlers themselves small; all logic lives
in the modules above.

Endpoints: POST /enroll, POST /checkin, GET /leaderboard?scenario=...,
GET /health.
"""


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()
