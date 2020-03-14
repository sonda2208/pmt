# pmt
Google PaymentMethodToken verifier

```go
d, err := pmt.NewGPayKeysDownloader(pmt.WithEndpoint(pmt.GooglePassesKeysURL))
// handle error here

m, err := pmt.NewGPayPublicKeysManager(pmt.WithKeysDownloader(d))
// handle error here

r, err := pmt.NewPaymentMethodTokenRecipient(
    pmt.WithProtocolVersion(pmt.ECv2SigningOnly),
    pmt.WithSenderID("GooglePayPasses"),
    pmt.WithRecipientID("<your issuer ID>"),
    pmt.WithKeysManager(m),
)
// handle error here

sealedMessage := []byte(`<sealed message from Google>`)
msg, err := r.Unseal(sealedMessage)
// handle error here
// use "msg" to extract the details
```