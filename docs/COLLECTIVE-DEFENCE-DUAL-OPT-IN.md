# Collective Defence dual opt-in policy

Collective Defence is secondary to Enterprise's customer-hosted resource-sharing
purpose. Signal sharing is denied unless the organisation and each participating
device owner have explicitly opted in and an operator has approved the request.
Only allowlisted defensive indicators may be shared. Raw file content and
personal data are prohibited; unknown classification is treated as prohibited.

This is a deterministic policy primitive, not a network sender or endpoint
response system. It does not deploy agents, quarantine devices, block traffic,
or perform remediation. Production integration must revalidate consent at the
transmission boundary, prove zero bytes are sent on denial, and provide immediate
opt-out, audit, rollback and customer-selected tooling. Remote execution and
autonomous containment remain disabled.
