# HTTP test accounts (neutral)

  test-user-a / HalcyonTestA!   (role: member)
  test-user-b / HalcyonTestB!   (role: member)

Log in at POST /login (form fields username, password; send
Accept: application/json for a JSON response and a session cookie). Use a
requests.Session to keep the cookie. Both are low-privilege members; that is the
point of the access-control proofs.
