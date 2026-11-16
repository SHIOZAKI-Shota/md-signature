package cli

import (
	"context"
	"strings"

	"github.com/SHIOZAKI-Shota/md-signature/mdsig"
)

// --- per-run resolver cache

type resolveOutcome struct {
	res mdsig.ResolveResult
	err error
}

type cachingResolver struct {
	method string
	inner  mdsig.Resolver
	seen   map[string]resolveOutcome
}

// DoS: N blocks naming the same signer cost one lookup, not N timeouts
func (c *cachingResolver) Resolve(ctx context.Context, fields map[string]string, opts *mdsig.ResolveOptions) (mdsig.ResolveResult, error) {
	parts := []string{c.method}
	for _, k := range []string{"signer", "selector", "key_fp", "fpr", "alg"} {
		v, ok := fields[k]
		if ok {
			v = "=" + v
		}
		parts = append(parts, v)
	}
	// NUL cannot occur in a field value that passed validation
	key := strings.Join(parts, "\x00")
	if o, ok := c.seen[key]; ok {
		return o.res, o.err
	}
	res, err := c.inner.Resolve(ctx, fields, opts)
	c.seen[key] = resolveOutcome{res: res, err: err}
	return res, err
}

// tofu is left out: it reads the block's own pubkey and updates the TOFU store
func cachedResolvers(custom map[string]mdsig.Resolver) map[string]mdsig.Resolver {
	out := map[string]mdsig.Resolver{}
	for m, r := range mdsig.DefaultResolvers() {
		out[m] = r
	}
	for m, r := range custom {
		out[m] = r
	}
	for m, r := range out {
		if m != "tofu" {
			out[m] = &cachingResolver{method: m, inner: r, seen: map[string]resolveOutcome{}}
		}
	}
	return out
}
