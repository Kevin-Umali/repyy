// Package intel contains the dated, offline threat-intelligence snapshot.
// It performs no network access. Every entry must point to a primary source.
package intel

import "time"

// SnapshotVersion and SnapshotDate identify the embedded intelligence revision.
const (
	SnapshotVersion = "2026-09-12.1"
	SnapshotDate    = "2026-09-12"
)

// Package is an attributable malicious-package intelligence record.
type Package struct {
	Ecosystem       string   `json:"ecosystem"`
	Name            string   `json:"name"`
	Severity        string   `json:"severity"`
	Source          string   `json:"source"`
	SourceURL       string   `json:"source_url"`
	AdvisoryID      string   `json:"advisory_id"`
	Description     string   `json:"description"`
	Added           string   `json:"added"`
	Modified        string   `json:"modified,omitempty"`
	Affected        []string `json:"affected_versions,omitempty"`
	TyposquatOf     string   `json:"typosquat_of,omitempty"`
	Campaign        string   `json:"campaign,omitempty"`
	References      []string `json:"references,omitempty"`
	SnapshotVersion string   `json:"snapshot_version"`
}

type packageDetails struct {
	Description string
	Added       string
	Modified    string
	Affected    []string
	References  []string
}

// FileHash is a published SHA-256 indicator with provenance and campaign context.
type FileHash struct {
	SHA256          string   `json:"sha256"`
	Family          string   `json:"family"`
	Source          string   `json:"source_url"`
	SourceName      string   `json:"source"`
	Context         string   `json:"context"`
	Description     string   `json:"description"`
	Added           string   `json:"added"`
	Campaign        string   `json:"campaign,omitempty"`
	Actor           string   `json:"actor,omitempty"`
	References      []string `json:"references,omitempty"`
	SnapshotVersion string   `json:"snapshot_version"`
}

// Packages is a bounded snapshot of malware advisories returned by GitHub's
// Global Security Advisory API on SnapshotDate. Package identity is a review
// signal rather than proof about every possible version of a reused name.
var Packages = []Package{
	{Ecosystem: "npm", Name: "cors-parser", AdvisoryID: "GHSA-5g94-qjr8-2q72"},
	{Ecosystem: "npm", Name: "crossenv", AdvisoryID: "GHSA-c2m4-w5hm-vqjw"},
	{Ecosystem: "npm", Name: "lodahs", AdvisoryID: "GHSA-hm6q-r2jc-cpqh"},
	{Ecosystem: "npm", Name: "electorn", AdvisoryID: "GHSA-m3v2-6fvq-3972"},
	{Ecosystem: "npm", Name: "event-stream", AdvisoryID: "GHSA-mh6f-8j2x-4483"},
	{Ecosystem: "npm", Name: "flatmap-stream", AdvisoryID: "GHSA-9x64-5r7x-2q53"},
	{Ecosystem: "npm", Name: "bcrypts-js", AdvisoryID: "GHSA-h6cw-hrwc-f4wm"},
	{Ecosystem: "npm", Name: "mongose", AdvisoryID: "GHSA-894f-rw44-qrw5"},
	{Ecosystem: "npm", Name: "axios", Severity: "critical", Source: "microsoft-threat-intelligence", SourceURL: microsoftAxiosSource, AdvisoryID: "MSFT-2026-04-01-AXIOS", Description: "Compromised Axios npm releases identified by Microsoft", Added: "2026-04-01", Affected: []string{"= 1.14.1", "= 0.30.4"}, Campaign: "Sapphire Sleet Axios supply-chain compromise", References: []string{microsoftAxiosSource}},
	{Ecosystem: "npm", Name: "plain-crypto-js", Severity: "critical", Source: "microsoft-threat-intelligence", SourceURL: microsoftAxiosSource, AdvisoryID: "MSFT-2026-04-01-PLAIN-CRYPTO-JS", Description: "Compromised npm release identified by Microsoft", Added: "2026-04-01", Affected: []string{"= 4.2.1"}, Campaign: "Sapphire Sleet Axios supply-chain compromise", References: []string{microsoftAxiosSource}},
	{Ecosystem: "npm", Name: "tailwind-form-kit", AdvisoryID: "GHSA-p7c5-phj5-qm49"},
	{Ecosystem: "npm", Name: "cr-bot-common", AdvisoryID: "GHSA-mjmf-5pc4-pfrp"},
	{Ecosystem: "npm", Name: "greensaver", AdvisoryID: "GHSA-jfw2-6254-9cwg"},
	{Ecosystem: "npm", Name: "tracker-cloudflare", AdvisoryID: "GHSA-f874-m83r-9vqh"},
	{Ecosystem: "npm", Name: "@nimbusedge/auth", AdvisoryID: "GHSA-gr7r-8wrc-f3mw"},
	{Ecosystem: "pip", Name: "platform-telemetry-client", AdvisoryID: "GHSA-7767-763c-fxp3"},
	{Ecosystem: "pip", Name: "transfomers", AdvisoryID: "GHSA-2p95-qvc5-6rjq"},
	{Ecosystem: "pip", Name: "langgrap", AdvisoryID: "GHSA-crjm-2g45-pq97"},
	{Ecosystem: "pip", Name: "openaii", AdvisoryID: "GHSA-q5h5-h6mj-vhgv"},
	{Ecosystem: "pip", Name: "ollamaa", AdvisoryID: "GHSA-9gv4-vfjg-jjrm"},
	{Ecosystem: "rubygems", Name: "zzzltestfoobarxyz", AdvisoryID: "GHSA-g99x-552p-cw68"},
	{Ecosystem: "rubygems", Name: "zztxtwtmp13", AdvisoryID: "GHSA-4g38-gv6r-x2fh"},
	{Ecosystem: "rubygems", Name: "zztxtwtmp10", AdvisoryID: "GHSA-9382-vv7h-xjg3"},
	{Ecosystem: "rubygems", Name: "zztxtwtmp04", AdvisoryID: "GHSA-9895-v6m3-rp7r"},
	{Ecosystem: "rubygems", Name: "zzwandsxabc119", AdvisoryID: "GHSA-x6j4-mp63-8fq9"},
	{Ecosystem: "maven", Name: "org.mvnpm:posthog-node", AdvisoryID: "GHSA-5f38-2pgv-jhg6"},
	{Ecosystem: "maven", Name: "io.github.leetcrunch:scribejava-core", AdvisoryID: "GHSA-9c6j-xrpw-g32x"},
	{Ecosystem: "go", Name: "github.com/utilizedsun/layout", AdvisoryID: "GHSA-cvm3-cf32-fx43"},
	{Ecosystem: "go", Name: "github.com/BufferZoneCorp/go-weather-sdk", AdvisoryID: "GHSA-vwpg-jg98-m5x3"},
	{Ecosystem: "go", Name: "github.com/BufferZoneCorp/log-core", AdvisoryID: "GHSA-p5wx-rrp4-r4w9"},
	{Ecosystem: "go", Name: "github.com/shallowmulti/hypert", AdvisoryID: "GHSA-3j46-8f92-vjvq"},
	{Ecosystem: "go", Name: "github.com/ornatedoctrin/layout", AdvisoryID: "GHSA-2237-qq4x-m83q"},
	{Ecosystem: "rust", Name: "tinymember", AdvisoryID: "GHSA-jpmw-jcm2-3wcq"},
	{Ecosystem: "rust", Name: "append-only-vec", AdvisoryID: "GHSA-m9v3-f7h2-72cp"},
	{Ecosystem: "rust", Name: "internment", AdvisoryID: "GHSA-mxq3-8c5w-crcm"},
	{Ecosystem: "rust", Name: "aronenao", AdvisoryID: "GHSA-vqfg-g9r4-x39f"},
	{Ecosystem: "rust", Name: "proc-macro-en", AdvisoryID: "GHSA-4v73-396v-6ph9"},
	{Ecosystem: "composer", Name: "intercom/intercom-php", AdvisoryID: "GHSA-45gr-fjmv-r4rw"},
	{Ecosystem: "nuget", Name: "stripeapi.net", AdvisoryID: "GHSA-v22p-9fwv-76r7"},
	{Ecosystem: "nuget", Name: "Zendesk-Api", AdvisoryID: "GHSA-vc2w-9pj4-6qch"},
	{Ecosystem: "nuget", Name: "Ultimate.Wpf.Toolkit", AdvisoryID: "GHSA-m9mf-f7gx-x34w"},
	{Ecosystem: "nuget", Name: "wpfuihelpercore", AdvisoryID: "GHSA-7vqr-5mvp-48qr"},
	{Ecosystem: "nuget", Name: "YoutubeExtractor.Net", AdvisoryID: "GHSA-jxgw-32v7-h9hc"},
}

func init() {
	for i := range Packages {
		entry := &Packages[i]
		if entry.Severity == "" {
			entry.Severity = "high"
		}
		if entry.Source == "" {
			entry.Source = "github-advisory-database"
		}
		if entry.SourceURL == "" {
			entry.SourceURL = "https://github.com/advisories/" + entry.AdvisoryID
		}
		entry.SnapshotVersion = SnapshotVersion
		if details, ok := packageDetailsByAdvisory[entry.AdvisoryID]; ok {
			entry.Description = details.Description
			entry.Added = details.Added
			entry.Modified = details.Modified
			entry.Affected = append([]string(nil), details.Affected...)
			entry.References = append([]string(nil), details.References...)
		} else if entry.Description == "" {
			entry.Description = "Confirmed malware advisory for " + entry.Name
			entry.Added = SnapshotDate
			entry.References = []string{entry.SourceURL}
		}
	}
	for i := range FileHashes {
		entry := &FileHashes[i]
		entry.SnapshotVersion = SnapshotVersion
		entry.References = []string{entry.Source}
		entry.Description = entry.Family + " indicator: " + entry.Context
		if entry.Source == unit42Source {
			entry.SourceName, entry.Added, entry.Campaign, entry.Actor = "Palo Alto Networks Unit 42", "2024-10-09", "Contagious Interview", "DPRK-associated CL-STA-0240"
		} else {
			entry.SourceName, entry.Added, entry.Campaign, entry.Actor = "Microsoft Threat Intelligence", "2026-04-01", "Axios supply-chain compromise", "Sapphire Sleet"
		}
	}
}

const unit42Source = "https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/"
const microsoftAxiosSource = "https://www.microsoft.com/en-us/security/blog/2026/04/01/mitigating-the-axios-npm-supply-chain-compromise/"

// FileHashes are SHA-256 IOCs published by Unit 42 for BeaverTail installers,
// BeaverTail executables, and InvisibleFerret-related components.
var FileHashes = []FileHash{
	{SHA256: "000b4a77b1905cabdb59d2b576f6da1b2ef55a0258004e4a9e290e9f41fb6923", Family: "BeaverTail", Source: unit42Source, Context: "macOS DMG"},
	{SHA256: "9abf6b93eafb797a3556bea1fe8a3b7311d2864d5a9a3687fce84bc1ec4a428c", Family: "BeaverTail", Source: unit42Source, Context: "macOS DMG"},
	{SHA256: "0f5f0a3ac843df675168f82021c24180ea22f764f87f82f9f77fe8f0ba0b7132", Family: "BeaverTail", Source: unit42Source, Context: "macOS Mach-O"},
	{SHA256: "d801ad1beeab3500c65434da51326d7648a3c54923d794b2411b7b6a2960f31e", Family: "BeaverTail", Source: unit42Source, Context: "macOS Mach-O"},
	{SHA256: "36cac29ff3c503c2123514ea903836d5ad81067508a8e16f7947e3e675a08670", Family: "BeaverTail", Source: unit42Source, Context: "Windows MSI"},
	{SHA256: "de6f9e9e2ce58a604fe22a9d42144191cfc90b4e0048dffcc69d696826ff7170", Family: "BeaverTail", Source: unit42Source, Context: "Windows MSI"},
	{SHA256: "fd9e8fcc5bda88870b12b47cbb1cc8775ccff285f980c4a2b683463b26e36bf0", Family: "BeaverTail", Source: unit42Source, Context: "Windows MSI"},
	{SHA256: "0621d37818c35e2557fdd8a729e50ea662ba518df8ca61a44cc3add5c6deb3cd", Family: "BeaverTail", Source: unit42Source, Context: "Windows EXE"},
	{SHA256: "9e3a9dbf10793a27361b3cef4d2c87dbd3662646f4470e5242074df4cb96c6b4", Family: "BeaverTail", Source: unit42Source, Context: "Windows EXE"},
	{SHA256: "d5c0b89e1dfbe9f5e5b2c3f745af895a36adf772f0b72a22052ae6dfa045cea6", Family: "BeaverTail", Source: unit42Source, Context: "Windows EXE"},
	{SHA256: "07183a60ebcb02546c53e82d92da3ddcf447d7a1438496c4437ec06b4d9eb287", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "10f86be3e564f2e463e45420eb5f9fbdb14f7427eac665cd9cc7901efbc4cc59", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "1c218d15b35b79d762b966db8bc2ca90fc62a95903bd78ac85648de1d828dbce", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "34170bda5eb84d737577096438a776a968cb36eff88817f12317edcb9d144b35", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "4343fa4e313a61f10de08fa5b1b8acb98589faf5739ab5b606f540983b630f79", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "486a9a79bbb81abee2e81679ace6267c3f3e37d9b8c8074f9ec7aebc9be75cdd", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "589e22005aa166b207a7aa7384dd3c7f90b71775688e587108801c3894a43358", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "5e820d8b2bd139b3018574c349cd48ce77e7b31cf85e9462712167fcab99b30a", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "6e065f1e4d1d8232da5de830d270a13fff8284a91e81c060377ebe66aa75d81d", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "8563eecbc85a0c43b689b9d9f31fe5977e630c276dee0d7dbfe1a47ab1ab4550", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "8de446957ce96826628c88da9fd4e7ff9d6327d8004afc4e9e86d59e7d6948dc", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "9ece783ac52c9ec2f6bdfa669763a7ed1bbb24af1e04e029a0a91954582690cf", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "a69e89a62203b8f2f89ec12a13e46c71b6b4d505deb19527ff73fd002df9bc6b", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "ad8a819d7b68905fa6a8425295755c329504dd0bb48b2fba8dd17e54562b0c6f", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "b9be6b0ac414ac2a033c17c3ac649417e97e5d0580db796a8ff55169299de50e", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "cde5afd20b7bb5c9457b68e02c13094125025fb974df425020361303dc6fcdfc", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "d0a5b9dc988834cc930624661e6e7dd1943d480d75594fff0f4bc39d229c5999", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "e0568196f1494137a5bbee897a37bc4fe15f87175b57a30403450a88486190c4", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "f08e88c7397443e35697e145887af2683a83d2415ccd0c7536cea09e35da9ef7", Family: "InvisibleFerret", Source: unit42Source, Context: "related component"},
	{SHA256: "92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a", Family: "Sapphire Sleet Axios RAT", Source: microsoftAxiosSource, Context: "macOS payload"},
	{SHA256: "ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c", Family: "Sapphire Sleet Axios RAT", Source: microsoftAxiosSource, Context: "Windows PowerShell payload"},
	{SHA256: "617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101", Family: "Sapphire Sleet Axios RAT", Source: microsoftAxiosSource, Context: "Windows PowerShell payload"},
	{SHA256: "f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd", Family: "Sapphire Sleet Axios RAT", Source: microsoftAxiosSource, Context: "Windows batch payload"},
	{SHA256: "fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf", Family: "Sapphire Sleet Axios RAT", Source: microsoftAxiosSource, Context: "Linux loader"},
}

// SnapshotTime returns SnapshotDate as UTC calendar time.
func SnapshotTime() time.Time {
	t, _ := time.Parse("2006-01-02", SnapshotDate)
	return t
}

// Stale reports whether the embedded snapshot is older than its 90-day policy.
func Stale(now time.Time) bool {
	return now.After(SnapshotTime().AddDate(0, 0, 90))
}
