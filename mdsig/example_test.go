package mdsig_test

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"mdsig.dev/mdsig"
)

func exampleSigner(b byte) mdsig.KeySigner {
	s, err := mdsig.SignerFromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		panic(err)
	}
	return s
}

func ExampleSignDocument() {
	ctx := context.Background()
	doc := "# Agreement\n\nThe parties agree.\n"

	signed, err := mdsig.SignDocument(ctx, doc, mdsig.SignOptions{
		Signer: exampleSigner(1), Method: "tofu", SignerID: "alice@laptop", Role: "author",
	})
	if err != nil {
		panic(err)
	}
	cosigned, err := mdsig.SignDocument(ctx, signed.Text, mdsig.SignOptions{
		Signer: exampleSigner(2), Method: "tofu", SignerID: "bob@laptop", Role: "reviewer",
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(strings.HasPrefix(cosigned.Text, doc))
	fmt.Println(strings.Count(cosigned.Text, "<!-- md-signature"))
	// Output:
	// true
	// 2
}

func ExampleVerifyDocument() {
	ctx := context.Background()
	signed, err := mdsig.SignDocument(ctx, "# Agreement\n", mdsig.SignOptions{
		Signer: exampleSigner(1), Method: "tofu", SignerID: "alice@laptop", Role: "author",
	})
	if err != nil {
		panic(err)
	}

	client := mdsig.SafeHTTPClient(15 * time.Second)
	opts := &mdsig.VerifyOptions{
		ResolveOptions:       mdsig.ResolveOptions{HTTPClient: client, PGPClient: client, TofuStore: &mdsig.MemoryTofuStore{}},
		ResourceCheckOptions: mdsig.ResourceCheckOptions{FetchClient: client},
	}

	r := mdsig.VerifyDocument(ctx, signed.Text, opts)
	for _, s := range r.Signatures {
		fmt.Println(s.Index, s.Status, s.Fields["signer"], s.Fields["role"])
	}

	tampered := strings.Replace(signed.Text, "Agreement", "Agreement (v2)", 1)
	for _, s := range mdsig.VerifyDocument(ctx, tampered, opts).Signatures {
		fmt.Println(s.Index, s.Status, s.Code)
	}
	// Output:
	// 1 valid alice@laptop author
	// 1 invalid hash-mismatch
}

func ExampleToJSON() {
	ctx := context.Background()
	signed, err := mdsig.SignDocument(ctx, "# Agreement\n", mdsig.SignOptions{
		Signer: exampleSigner(1), Method: "tofu", SignerID: "alice@laptop",
	})
	if err != nil {
		panic(err)
	}
	out := mdsig.ToJSON(mdsig.VerifyDocument(ctx, signed.Text, &mdsig.VerifyOptions{
		ResolveOptions: mdsig.ResolveOptions{Offline: true, TofuStore: &mdsig.MemoryTofuStore{}},
	}))
	fmt.Println(out.OK, len(out.Signatures), out.Agreement.Status)
	// Output:
	// true 1 none
}
