TRANSACTION_STATES = [
    ('init', 'Initiated by requester'),
    ('accepted', 'Lender ready to share'),
    ('rejected', 'Lender rejects request'),         # Final state
    ('shared', 'ekyc shared with requester'),
    ('commited', 'Address updated successfully'),    # Final state
    ('aborted', 'Aborted due to any reason'),       # Final state
]