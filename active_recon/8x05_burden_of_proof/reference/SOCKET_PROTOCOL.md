# Diagnostic service protocol (neutral)

  halcyon.example:16379, line-oriented over TCP (CRLF). On connect a banner line
  is sent. Safe commands:
    PING        -> +PONG
    INFO        -> server info lines
    AUTHCHECK   -> whether authentication is required for the open command set
    ADMINSTATS  -> a privileged command
    QUIT        -> close

  Read the live responses from your own socket code. What each response means for
  the finding is yours to decide.
