package pmt

type KeysDownloaderOption func(*GPayKeysDownloader)

func WithEndpoint(url string) KeysDownloaderOption {
	return func(downloader *GPayKeysDownloader) {
		downloader.url = url
	}
}

type GPayPublicKeysManagerOption func(*GPayPublicKeysManager)

func WithKeysDownloader(downloader KeysDownloader) GPayPublicKeysManagerOption {
	return func(manager *GPayPublicKeysManager) {
		manager.downloader = downloader
	}
}

type PaymentMethodTokenRecipientOption func(*PaymentMethodTokenRecipient)

func WithProtocolVersion(version ProtocolVersion) PaymentMethodTokenRecipientOption {
	return func(recipient *PaymentMethodTokenRecipient) {
		recipient.protocolVersion = version
	}
}

func WithSenderID(id string) PaymentMethodTokenRecipientOption {
	return func(recipient *PaymentMethodTokenRecipient) {
		recipient.senderID = id
	}
}

func WithRecipientID(id string) PaymentMethodTokenRecipientOption {
	return func(recipient *PaymentMethodTokenRecipient) {
		recipient.recipientID = id
	}
}

func WithKeysManager(manager PublicKeysManager) PaymentMethodTokenRecipientOption {
	return func(recipient *PaymentMethodTokenRecipient) {
		recipient.keysManager = manager
	}
}
