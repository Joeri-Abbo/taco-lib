package vulndb

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

const (
	// VulnDBMediaType is the media type for the vulndb JSON layer.
	VulnDBMediaType types.MediaType = "application/vnd.taco.vulndb.layer.v1+json.gz"
	// VulnDBConfigMediaType is the media type for the config blob.
	VulnDBConfigMediaType types.MediaType = "application/vnd.taco.vulndb.config.v1+json"
)

// OCIMetadata is stored as the OCI image config, carrying DB metadata.
type OCIMetadata struct {
	LastUpdated   time.Time             `json:"last_updated"`
	EntryCount    int                   `json:"entry_count"`
	Sources       map[string]SourceMeta `json:"sources,omitempty"`
	SchemaVersion int                   `json:"schema_version"`
}

// PushOCI pushes the cached vulnerability database to an OCI registry as an artifact.
// The reference should be something like: ghcr.io/jabbo/taco-vulndb:latest
func PushOCI(cache *Cache, ref string) error {
	if !cache.Exists() {
		return fmt.Errorf("no cached database found; run 'taco db update' first")
	}

	// Parse the target reference.
	tag, err := name.NewTag(ref)
	if err != nil {
		return fmt.Errorf("parsing OCI reference %q: %w", ref, err)
	}

	// Read the DB file.
	dbData, err := os.ReadFile(cache.DBPath())
	if err != nil {
		return fmt.Errorf("reading database: %w", err)
	}

	// Gzip the data and create a static layer with a standard OCI media type.
	var gzBuf bytes.Buffer
	gz := gzip.NewWriter(&gzBuf)
	if _, err := gz.Write(dbData); err != nil {
		return fmt.Errorf("compressing layer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("closing gzip writer: %w", err)
	}
	layer := static.NewLayer(gzBuf.Bytes(), types.OCILayer)

	// Build the image: empty base + DB layer.
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)

	img, err = mutate.AppendLayers(img, layer)
	if err != nil {
		return fmt.Errorf("appending layer: %w", err)
	}

	// Embed metadata as annotations on the manifest.
	meta, _ := cache.ReadMeta()
	annotations := map[string]string{
		"org.taco.vulndb.schema_version": "1",
	}
	if meta != nil {
		annotations["org.taco.vulndb.entry_count"] = fmt.Sprintf("%d", meta.EntryCount)
		annotations["org.taco.vulndb.last_updated"] = meta.LastUpdated.UTC().Format(time.RFC3339)
	}
	img = mutate.Annotations(img, annotations).(v1.Image)

	// Push to registry with default auth (Docker config / GITHUB_TOKEN).
	if err := remote.Write(tag, img, remote.WithAuthFromKeychain(authn.DefaultKeychain)); err != nil {
		return fmt.Errorf("pushing to %s: %w", ref, err)
	}

	return nil
}

// PullOCI pulls a vulnerability database OCI artifact and installs it into the cache.
// The reference should be something like: ghcr.io/jabbo/taco-vulndb:latest
func PullOCI(cache *Cache, ref string) error {
	// Parse the reference.
	imgRef, err := name.ParseReference(ref)
	if err != nil {
		return fmt.Errorf("parsing OCI reference %q: %w", ref, err)
	}

	// Pull the image.
	img, err := remote.Image(imgRef, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return fmt.Errorf("pulling %s: %w", ref, err)
	}

	// Extract the DB layer (first layer).
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("getting layers: %w", err)
	}
	if len(layers) == 0 {
		return fmt.Errorf("OCI artifact has no layers")
	}

	// The layer is gzip-compressed; Uncompressed() gives us the raw JSON.
	rc, err := layers[0].Uncompressed()
	if err != nil {
		return fmt.Errorf("decompressing layer: %w", err)
	}
	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("reading layer data: %w", err)
	}

	// Validate it's a valid DB.
	var entries []DBEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("invalid database in OCI artifact: %w", err)
	}

	// Write to cache.
	if err := cache.WriteDB(entries); err != nil {
		return fmt.Errorf("writing to cache: %w", err)
	}

	// Extract metadata from manifest annotations.
	cacheMeta := &CacheMeta{
		LastUpdated: time.Now(),
		EntryCount:  len(entries),
		SourceURL:   "oci://" + ref,
	}
	manifest, err := img.Manifest()
	if err == nil && manifest != nil {
		if t, parseErr := time.Parse(time.RFC3339, manifest.Annotations["org.taco.vulndb.last_updated"]); parseErr == nil {
			cacheMeta.LastUpdated = t
		}
	}
	_ = cache.WriteMeta(cacheMeta)

	return nil
}
