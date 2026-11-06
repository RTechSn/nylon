// nylon-genesis generates AWG 2.0 obfuscation profiles for nylon meshes.
//
// This binary links the GPL-3.0 amnezigo parameter oracle, so distributed
// builds of it are conveyed under the GPL-3.0 (see LICENSE.GPL-3.0): anyone
// redistributing the binary must pass on the license and the corresponding
// source. The nylon daemon links only MIT device code and Apache-2.0 nylon
// code and carries no copyleft obligations.
package main

import (
	"fmt"
	"os"
	"slices"

	amnezigo "github.com/Arsolitt/amnezigo"
	"github.com/encodeous/nylon/internal/buildinfo"
	"github.com/encodeous/nylon/internal/logging"
	"github.com/encodeous/nylon/state"
	"github.com/goccy/go-yaml"
	"github.com/spf13/cobra"
)

const defaultPreset = "standard-1420"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		presetName    string
		random        bool
		protocol      string
		mtu           int
		strategyName  string
		strategyPorts string
		compat        bool
		outPath       string
		verbose       bool
	)

	cmd := &cobra.Command{
		Use:   "nylon-genesis",
		Short: "Generate an AWG 2.0 obfuscation fragment for a nylon central config",
		Long: `Generates a paste-ready YAML fragment: the global obf block — the
mesh-wide shared S/H handshake dialect (s1-s4, h1-h4, uniform by
construction: wire compatibility requires it) plus ONE named strategy under
obf.strategy carrying the sender-local junk emission (the jc/jmin/jmax trio
and the I1-I5 CPS sequences).

The strategy lands in the central config's obf.strategy map; tag endpoints
with the strategy name (host[<strategy>]) to use it, and adjust its ports to
your deployment. Parameters come from the amnezigo oracle and are validated
before anything is emitted.

--compat emits the fixed vanilla-compat profile (H1..H4 pinned to the
WireGuard message types, no padding/junk/I) for the version-skew window
where plain-WireGuard peers must interoperate.`,
		Version:      buildinfo.Version,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(presetName, random, protocol, mtu, strategyName, strategyPorts, compat, outPath, verbose)
		},
	}

	cmd.Flags().StringVar(&presetName, "preset", defaultPreset, "amnezigo preset name for the shared profile")
	cmd.Flags().BoolVar(&random, "random", false, "generate a random profile via amnezigo GenerateConfig instead of a preset")
	cmd.Flags().StringVar(&protocol, "protocol", amnezigo.ProtocolRandom, "protocol template for the strategy's I1-I5 (quic|dns|dtls|stun|sip|rtp|random)")
	cmd.Flags().IntVar(&mtu, "mtu", 0, "underlay MTU clamping for I/junk sizes (0 = preset default)")
	cmd.Flags().StringVar(&strategyName, "strategy", "", "name of the generated obf strategy (default: the protocol template name)")
	cmd.Flags().StringVar(&strategyPorts, "strategy-ports", "51820", "ports of the generated obf strategy (a single port or an inclusive range; adjust to your deployment)")
	cmd.Flags().BoolVar(&compat, "compat", false, "emit the fixed vanilla-compat profile (ignores preset/protocol)")
	cmd.Flags().StringVar(&outPath, "out", "", "write to FILE instead of stdout")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "log debug detail to stderr")

	return cmd
}

// outputFragment mirrors the CentralCfg yaml shape so the output is
// paste-ready and unmarshals into state.CentralCfg without noise fields: the
// global obf block carries the mesh-wide S/H dialect inline plus the named
// strategy map under `strategy:` (see state.CentralObf). One strategy
// carries one shared junk configuration (the jc/jmin/jmax trio and the
// I-set, per the config reform — see state.ObfStrategy).
type outputFragment struct {
	Obf *state.CentralObf `yaml:"obf,omitempty"`
}

// genJunk is the sender-local junk trio drawn for the strategy (the AWG J
// params — per-strategy knobs under the config reform).
type genJunk struct {
	jc, jmin, jmax uint32
}

func run(presetName string, random bool, protocol string, mtu int, strategyName string, strategyPorts string, compat bool, outPath string, verbose bool) error {
	level, err := logging.Resolve("", verbose)
	if err != nil {
		return err
	}
	log, closer, err := logging.New(logging.Config{Component: "nylon-genesis", Level: level, JSON: false})
	if err != nil {
		return err
	}
	defer closer()
	if !slices.Contains(amnezigo.ListProtocols(), protocol) {
		return fmt.Errorf("unknown protocol %q; valid: %v", protocol, amnezigo.ListProtocols())
	}
	if strategyName == "" {
		strategyName = protocol
	}
	if err := state.NameValidator(strategyName); err != nil {
		return fmt.Errorf("invalid strategy name: %w", err)
	}
	if _, err := state.ParsePortRange(strategyPorts); err != nil {
		return fmt.Errorf("invalid --strategy-ports %q: %w", strategyPorts, err)
	}

	preset, err := amnezigo.GetPreset(presetName)
	if err != nil {
		return err
	}
	if mtu == 0 {
		mtu = preset.MTU
	}

	var profile state.ObfProfile
	var junk genJunk
	var iSet [5]string

	if compat {
		// The compat profile deliberately pins H1..H4 to the vanilla WG
		// message type ids; header-range validation is skipped because
		// excluding 1..4 is exactly what it would reject. No junk.
		profile = state.ObfProfile{
			H1: state.ObfHeaderRange{Min: 1, Max: 1},
			H2: state.ObfHeaderRange{Min: 2, Max: 2},
			H3: state.ObfHeaderRange{Min: 3, Max: 3},
			H4: state.ObfHeaderRange{Min: 4, Max: 4},
		}
		if err := profile.Validate(); err != nil {
			return fmt.Errorf("internal error: compat profile invalid: %w", err)
		}
	} else {
		if random {
			// One attempt draws the shared S/H dialect (mesh-uniform
			// by construction) plus the strategy's junk trio and
			// I-set; a draw can collide an I-packet length with a
			// padded handshake size, so the whole attempt is redrawn
			// until it validates.
			profile, junk, iSet, err = generateRandomProfile(protocol, mtu, preset.S1, preset.Jc)
			if err != nil {
				return err
			}
			log.Debug("validated profile")
		} else {
			server := preset.ToServerObfuscation()
			profile = profileFromServer(server)
			junk = junkFromServer(server)

			if err := validateGenerated(&profile, junk, server); err != nil {
				return err
			}
			log.Debug("validated profile")

			iSet, err = generateISet(&profile, junk, protocol, mtu)
			if err != nil {
				return err
			}
		}
		log.Debug("validated strategy junk", "strategy", strategyName, "template", protocol)
	}

	strat := &state.ObfStrategy{
		Ports: strategyPorts,
		I1:    iSet[0], I2: iSet[1], I3: iSet[2], I4: iSet[3], I5: iSet[4],
	}
	if junk.jc > 0 {
		// a junk-free strategy emits no jc/jmin/jmax keys at all; a zero
		// trio would be dead config the validator rejects
		strat.Jc, strat.Jmin, strat.Jmax = &junk.jc, &junk.jmin, &junk.jmax
	}
	frag := outputFragment{
		Obf: &state.CentralObf{
			ObfProfile: profile,
			Strategy:   map[string]*state.ObfStrategy{strategyName: strat},
		},
	}

	output := outPath
	if output == "" {
		output = "stdout"
	}
	log.Info("generated obf fragment", "preset", presetName, "protocol", protocol, "mtu", mtu, "strategy", strategyName, "ports", strategyPorts, "output", output)

	data, err := yaml.Marshal(frag)
	if err != nil {
		return err
	}

	if outPath != "" {
		return os.WriteFile(outPath, data, 0o644)
	}
	_, err = os.Stdout.Write(data)
	return err
}

// randomProfileAttempts bounds both redraw loops: generateRandomProfile
// redraws the shared S/H dialect plus the strategy's junk trio, and
// generateISet redraws the strategy's I-set. A draw fails when an I-packet
// length collides with one of the four padded handshake sizes. Protocol
// "random" was measured to fail ~45% of runs per attempt (amnezigo
// measurement at 5 peers), and the worst realistic profiles stay below
// that, so 64 attempts put the residual failure probability under 1e-20
// (the two loops nest, so an I-set draw that needs several attempts still
// gets a fresh shared profile afterwards).
const randomProfileAttempts = 64

// generateRandomProfile draws an amnezigo random profile: one shared
// mesh-uniform S/H dialect per attempt plus the strategy's junk trio and
// I-set, the same shape the preset path emits. Every attempt is validated
// with the same validators as the preset path (validateGenerated, then the
// I-set size check); the first fully valid attempt wins, and an invalid
// attempt is redrawn rather than surfaced, because a padded-size collision
// is an artifact of a single random draw and not a property of the inputs.
func generateRandomProfile(protocol string, mtu, s1, jc int) (state.ObfProfile, genJunk, [5]string, error) {
	var lastErr error
	for range randomProfileAttempts {
		server := amnezigo.GenerateConfig(protocol, mtu, s1, jc).ServerObfuscationConfig
		profile := profileFromServer(server)
		junk := junkFromServer(server)
		if err := validateGenerated(&profile, junk, server); err != nil {
			lastErr = err
			continue
		}

		iSet, err := generateISet(&profile, junk, protocol, mtu)
		if err != nil {
			lastErr = err
			continue
		}
		return profile, junk, iSet, nil
	}
	return state.ObfProfile{}, genJunk{}, [5]string{}, fmt.Errorf("no valid random profile after %d attempts: %w", randomProfileAttempts, lastErr)
}

// generateISet draws the strategy's I1-I5 until it satisfies the size
// invariant against profile, redrawing a colliding draw (a padded handshake
// size). Public amnezigo GenerateCPS draws against an empty forbidden set —
// its documentation defers collision avoidance to GenerateConfig — so a draw
// collides with a padded handshake size now and then. With the random
// protocol the I lengths vary per draw and a redraw resolves it; a named
// template has one fixed length per (protocol, mtu, S1), so an incompatible
// combination simply never validates and the budget turns it into one clear
// error instead of a coin flip.
func generateISet(profile *state.ObfProfile, junk genJunk, protocol string, mtu int) ([5]string, error) {
	var lastErr error
	for range randomProfileAttempts {
		i1, i2, i3, i4, i5 := amnezigo.GenerateCPS(protocol, mtu, int(profile.S1), 0)
		iSet := [5]string{i1, i2, i3, i4, i5}
		if err := validateISet(profile, junk, iSet); err != nil {
			lastErr = err
			continue
		}
		return iSet, nil
	}
	return [5]string{}, fmt.Errorf("no collision-free I-set in %d draws: %w", randomProfileAttempts, lastErr)
}

func profileFromServer(s amnezigo.ServerObfuscationConfig) state.ObfProfile {
	hr := func(h amnezigo.HeaderRange) state.ObfHeaderRange {
		return state.ObfHeaderRange{Min: h.Min, Max: h.Max}
	}
	return state.ObfProfile{
		S1: uint32(s.S1),
		S2: uint32(s.S2),
		S3: uint32(s.S3),
		S4: uint32(s.S4),
		H1: hr(s.H1),
		H2: hr(s.H2),
		H3: hr(s.H3),
		H4: hr(s.H4),
	}
}

// junkFromServer extracts the sender-local junk trio from an amnezigo
// server config: it rides the strategy, not the mesh-wide profile.
func junkFromServer(s amnezigo.ServerObfuscationConfig) genJunk {
	return genJunk{jc: uint32(s.Jc), jmin: uint32(s.Jmin), jmax: uint32(s.Jmax)}
}

// validateGenerated runs the amnezigo validators over the shared profile:
// header-range viability plus the size-classification invariant for the
// S-padded handshake sizes and the junk range. (amnezigo's ValidateServerConfig
// additionally requires interface fields a profile fragment does not carry,
// so its obfuscation sub-checks are invoked directly instead.)
func validateGenerated(profile *state.ObfProfile, junk genJunk, server amnezigo.ServerObfuscationConfig) error {
	if err := profile.Validate(); err != nil {
		return fmt.Errorf("invalid obf profile: %w", err)
	}
	for i, h := range []amnezigo.HeaderRange{server.H1, server.H2, server.H3, server.H4} {
		if err := amnezigo.ValidateHeaderRange(h); err != nil {
			return fmt.Errorf("h%d: %w", i+1, err)
		}
	}
	if err := amnezigo.ValidatePacketSizes(
		int(profile.S1), int(profile.S2), int(profile.S3), int(profile.S4),
		nil, int(junk.jmin), int(junk.jmax),
	); err != nil {
		return fmt.Errorf("profile sizes: %w", err)
	}
	return nil
}

// validateISet re-checks the size-classification invariant with the freshly
// generated strategy I lengths.
func validateISet(profile *state.ObfProfile, junk genJunk, iSet [5]string) error {
	iSizes := []int{
		amnezigo.CPSLength(iSet[0]),
		amnezigo.CPSLength(iSet[1]),
		amnezigo.CPSLength(iSet[2]),
		amnezigo.CPSLength(iSet[3]),
		amnezigo.CPSLength(iSet[4]),
	}
	return amnezigo.ValidatePacketSizes(
		int(profile.S1), int(profile.S2), int(profile.S3), int(profile.S4),
		iSizes, int(junk.jmin), int(junk.jmax),
	)
}
