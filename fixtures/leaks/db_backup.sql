-- nightly_dump (accidentally uploaded)
CREATE TABLE customers (
  id SERIAL PRIMARY KEY,
  full_name TEXT,
  email TEXT,
  phone TEXT,
  dob DATE,
  ssn TEXT,
  address TEXT
);

INSERT INTO customers (full_name, email, phone, dob, ssn, address) VALUES
('Alice Smith', 'alice.smith@example.com', '+1-555-014-2233', '1992-04-17', '000-12-3456', '123 Example Ave, Example City, CA 94105'),
('Bob Johnson', 'bob.johnson@example.org', '+1-555-017-8899', '1988-11-02', '000-98-7654', '77 Sample Rd, Example Town, NY 10001');