CREATE TABLE repair_ticket (
    ticket_id BIGINT PRIMARY KEY,
    ticket_code VARCHAR(24) UNIQUE NOT NULL,
    customer_id VARCHAR(48) NOT NULL,
    frame_tag VARCHAR(40) NOT NULL,
    work_note VARCHAR(200) NOT NULL
);

CREATE TABLE pickup_slot (
    ticket_id BIGINT PRIMARY KEY REFERENCES repair_ticket(ticket_id),
    counter_note VARCHAR(120) NOT NULL
);
