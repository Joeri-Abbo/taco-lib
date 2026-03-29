package vulndb

import (
	"bytes"
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
	"github.com/google/go-containerregistry/pkg/v1/stream"
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

	// Create a gzipped stream layer from the DB data.
	layer := stream.NewLayer(io.NopCloser(bytes.NewReader(dbData)))

	// Build the image: empty base + DB layer.
	img := mutate.MediaType(empty.Image, types.OCIManifestSchema1)

	img, err = mutate.Append(img, mutate.Addendum{
		Layer:     layer,
		MediaType: VulnDBMediaType,
	})
	if err != nil {
		return fmt.Errorf("appending layer: %w", err)
	}

	// Build config with our metadata.
	meta, _ := cache.ReadMeta()
	ociMeta := OCIMetadata{
		SchemaVersion: 1,
		LastUpdated:   time.Now(),
	}
	if meta != nil {
		ociMeta.EntryCount = meta.EntryCount
		ociMeta.Sources = meta.Sources
		ociMeta.LastUpdated = meta.LastUpdated
	}

	// Embed metadata as annotations on the manifest since custom config
	// media types require more ceremony. Use labels in the config.
	configFile := &v1.ConfigFile{
		Config: v1.Config{
			Labels: map[string]string{
				"org.taco.vulndb.schema_version": "1",
				"org.taco.vulndb.entry_count":    fmt.Sprintf("%d", ociMeta.EntryCount),
				"org.taco.vulndb.last_updated":   ociMeta.LastUpdated.UTC().Format(time.RFC3339),
			},
		},
	}
	img, err = mutate.ConfigFile(img, configFile)
	if err != nil {
		return fmt.Errorf("setting config: %w", err)
	}

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

	// Extract metadata from config labels.
	configFile, err := img.ConfigFile()
	if err == nil && configFile != nil {
		cacheMeta := &CacheMeta{
			LastUpdated: time.Now(),
			EntryCount:  len(entries),
			SourceURL:   "oci://" + ref,
		}
		if t, parseErr := time.Parse(time.RFC3339, configFile.Config.Labels["org.taco.vulndb.last_updated"]); parseErr == nil {
			cacheMeta.LastUpdated = t
		}
		_ = cache.WriteMeta(cacheMeta)
	}

	return nil
}
