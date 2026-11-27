from fastapi import FastAPI, HTTPException, Depends
from .security import verify_jwt

app = FastAPI(title="Phase 4: Billing Microservice (RS256 Public Key Only)")


@app.get("/invoices")
def get_my_invoices(payload: dict = Depends(verify_jwt)):
	return {
		"service": "billing-service",
		"user": payload["sub"],
		"role": payload["role"],
		"invoices": [
			{"id": "INV-001", "amount": "$19.99", "stauts": "Paid"},
			{"id": "INV-002", "amount": "$19.99", "status": "Paid"}
		]
	}

@app.post("/refund/{invoice_id}")
def issue_refund(invoice_id: str, payload: dict = Depends(verify_jwt)):
	if payload.get("role") != "admin":
		raise HTTPException(status_code=403, detail="Only admins can issue refunds")

	return {
		"service": "billing-service",
		"message": f"Admin '{payload['sub']}' processed refund for {invoice_id}"
	}

