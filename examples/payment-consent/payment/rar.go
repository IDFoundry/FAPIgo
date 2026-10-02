package payment

import (
	"errors"
	"regexp"

	"github.com/idfoundry/fapigo/extension"
)

// The payment_initiation Rich Authorization Requests (RFC 9396) detail
// type, shaped as RFC 9396's own example.

type amount struct {
	Currency string `json:"currency"`
	Amount   string `json:"amount"` // decimal string, e.g. "129.00"
}

type account struct {
	IBAN string `json:"iban"`
}

// paymentInitiation asks to make one payment.
type paymentInitiation struct {
	InstructedAmount  amount  `json:"instructedAmount"`
	CreditorName      string  `json:"creditorName"`
	CreditorAccount   account `json:"creditorAccount"`
	RemittanceMessage string  `json:"remittanceInformationUnstructured,omitempty"`
}

var decimalAmount = regexp.MustCompile(`^[0-9]{1,6}\.[0-9]{2}$`)

var paymentInitiationType = extension.RARDefinition[paymentInitiation]{
	Type: "payment_initiation", MaxObjects: 1, MaxBytesPerObject: 1024,
	Validate: func(p paymentInitiation) error {
		if p.InstructedAmount.Currency != "EUR" || !decimalAmount.MatchString(p.InstructedAmount.Amount) {
			return errors.New("instructedAmount must be a EUR amount like 129.00")
		}
		if p.CreditorAccount.IBAN == "" {
			return errors.New("creditorAccount.iban is required")
		}
		return nil
	},
	// ValidateGrant is nil: a payment is approved exactly as asked, or
	// not at all.
}

func newRARRegistry() (*extension.RARRegistry, error) {
	return extension.NewRARRegistry(4096, 4, paymentInitiationType)
}

// paymentsOf is the payment_initiation details among values.
func paymentsOf(values extension.RARValues) []paymentInitiation {
	details, _ := extension.RARGet(values, paymentInitiationType)
	out := make([]paymentInitiation, len(details))
	for i, d := range details {
		out[i] = d.Fields
	}
	return out
}
