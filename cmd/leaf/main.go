package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/peterbourgon/ff/v3"
	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/joeshaw/leaf"
)

const (
	unitsMiles      = "mi"
	unitsKilometers = "km"
)

type config struct {
	username    string
	password    string
	country     string
	vin         string
	units       string
	sessionFile string
	debug       bool
}

func main() {
	var cfg config

	fs := flag.NewFlagSet("leaf", flag.ExitOnError)
	fs.StringVar(&cfg.username, "username", "", "Nissan username")
	fs.StringVar(&cfg.password, "password", "", "Nissan password")
	fs.StringVar(&cfg.country, "country", "US", "Vehicle country")
	fs.StringVar(&cfg.vin, "vin", "", "Request from a specific VIN")
	fs.StringVar(&cfg.units, "units", unitsMiles, "Units (mi/km)")
	fs.StringVar(&cfg.sessionFile, "session-file", "~/.leaf-session", "File to load/store session info")
	fs.BoolVar(&cfg.debug, "debug", false, "Print debugging output")

	root := &ffcli.Command{
		Name:       "leaf",
		ShortUsage: "leaf [flags] <subcommand> [flags] [arg...]",
		FlagSet:    fs,
		Options: []ff.Option{
			ff.WithConfigFile(filepath.Join(os.Getenv("HOME"), ".leaf")),
			ff.WithAllowMissingConfigFile(true),
			ff.WithConfigFileParser(ff.PlainParser),
			ff.WithEnvVarPrefix("LEAF"),
		},
		Exec: func(context.Context, []string) error {
			return flag.ErrHelp
		},
		Subcommands: []*ffcli.Command{
			infoCmd(&cfg),
			batteryCmd(&cfg),
			updateCmd(&cfg),
			climateOnCmd(&cfg),
			climateOffCmd(&cfg),
			chargeCmd(&cfg),
			locateCmd(&cfg),
		},
	}

	if err := root.ParseAndRun(context.Background(), os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func newSession(cfg *config) *leaf.Session {
	s := &leaf.Session{
		Username: cfg.username,
		Password: cfg.password,
		Country:  cfg.country,
		Debug:    cfg.debug,
		Filename: cfg.sessionFile,
		VIN:      cfg.vin,
	}

	if err := s.Load(); err != nil {
		fmt.Printf("Warning: unable to load session: %v\n", err)
	}

	return s
}

func infoCmd(cfg *config) *ffcli.Command {
	return &ffcli.Command{
		Name:       "info",
		ShortUsage: "leaf info",
		ShortHelp:  "Display vehicle info",
		Exec: func(ctx context.Context, args []string) error {
			fmt.Println("Getting vehicle info...")

			s := newSession(cfg)

			info, _, _, err := s.Login()
			if err != nil {
				return err
			}

			fmt.Printf("Vehicle info for %s:\n", info.Nickname)
			fmt.Printf("  VIN: %s\n", info.VIN)
			fmt.Printf("  Model: %s %s\n", info.ModelYear, info.ModelName)
			fmt.Printf("  Color: %s\n", info.ExtColor)
			fmt.Println()

			return nil
		},
	}
}

func batteryCmd(cfg *config) *ffcli.Command {
	return &ffcli.Command{
		Name:       "battery",
		ShortUsage: "leaf battery",
		ShortHelp:  "Display last battery status",
		Exec: func(ctx context.Context, args []string) error {
			fmt.Println("Getting last updated battery status...")

			s := newSession(cfg)

			_, br, _, err := s.Login()
			if err != nil {
				return err
			}

			printBatteryRecords(cfg, br)

			return nil
		},
	}
}

func updateCmd(cfg *config) *ffcli.Command {
	return &ffcli.Command{
		Name:       "update",
		ShortUsage: "leaf update",
		ShortHelp:  "Update Leaf battery status",
		Exec: func(ctx context.Context, args []string) error {
			fmt.Println("Requesting updated battery status...")

			s := newSession(cfg)

			br, _, err := s.ChargingStatus()
			if err != nil {
				return err
			}

			printBatteryRecords(cfg, br)

			return nil
		},
	}
}

func climateOnCmd(cfg *config) *ffcli.Command {
	return &ffcli.Command{
		Name:       "climate-on",
		ShortUsage: "leaf climate-on",
		ShortHelp:  "Turn the climate control system on",
		Exec: func(ctx context.Context, args []string) error {
			fmt.Println("Turning on climate-control...")

			s := newSession(cfg)

			if err := s.ClimateOn(); err != nil {
				return err
			}

			return nil
		},
	}
}

func climateOffCmd(cfg *config) *ffcli.Command {
	return &ffcli.Command{
		Name:       "climate-off",
		ShortUsage: "leaf climate-off",
		ShortHelp:  "Turn the climate control system off",
		Exec: func(ctx context.Context, args []string) error {
			fmt.Println("Turning off climate-control...")

			s := newSession(cfg)

			if err := s.ClimateOff(); err != nil {
				return err
			}

			return nil
		},
	}
}

func chargeCmd(cfg *config) *ffcli.Command {
	return &ffcli.Command{
		Name:       "charge",
		ShortUsage: "leaf charge",
		ShortHelp:  "Begin charging plugged-in vehicle",
		Exec: func(ctx context.Context, args []string) error {
			fmt.Println("Start charging...")

			s := newSession(cfg)

			if err := s.StartCharging(); err != nil {
				return err
			}

			return nil
		},
	}
}

func locateCmd(cfg *config) *ffcli.Command {
	return &ffcli.Command{
		Name:       "locate",
		ShortUsage: "leaf locate",
		ShortHelp:  "Locate vehicle",
		Exec: func(ctx context.Context, args []string) error {
			fmt.Println("Locating vehicle...")

			s := newSession(cfg)

			loc, err := s.LocateVehicle()
			if err != nil {
				return err
			}

			fmt.Printf("Vehicle location as of %s:\n", loc.ReceivedDate.Local())
			fmt.Printf("  Latitude: %s\n", loc.Latitude)
			fmt.Printf("  Longitude: %s\n", loc.Longitude)
			fmt.Printf("  Link: https://www.google.com/maps/place/%s,%s\n", loc.Latitude, loc.Longitude)
			fmt.Println()

			return nil
		},
	}
}

func printBatteryRecords(cfg *config, br *leaf.BatteryRecords) {
	fmt.Printf("Battery status as of %s:\n", br.LastUpdatedDateAndTime.Local())
	fmt.Printf("  Battery remaining: %d%%\n", br.BatteryStatus.BatteryRemainingAmount)
	if br.CruisingRangeACOn > 0 {
		fmt.Printf("  Cruising range: %s (%s with heat/AC)\n", prettyUnits(cfg.units, br.CruisingRangeACOff), prettyUnits(cfg.units, br.CruisingRangeACOn))
	}
	fmt.Printf("  Plug-in state: %s\n", br.PluginState)
	fmt.Printf("  Charging status: %s\n", br.BatteryStatus.BatteryChargingStatus)
	fmt.Printf("  Time to full:\n")
	if !br.TimeRequired.IsZero() {
		fmt.Printf("    Level 1 charge: %s\n", br.TimeRequired)
	}
	if !br.TimeRequired200.IsZero() {
		fmt.Printf("    Level 2 charge: %s\n", br.TimeRequired200)
	}
	if !br.TimeRequired200_6kW.IsZero() {
		fmt.Printf("    Level 2 at 6 kW: %s\n", br.TimeRequired200_6kW)
	}
	if br.TimeRequired.IsZero() && br.TimeRequired200.IsZero() && br.TimeRequired200_6kW.IsZero() {
		fmt.Printf("    (no time-to-full estimates available)\n")
	}
	fmt.Println()

}

func prettyUnits(units string, meters float64) string {
	switch units {
	case unitsMiles:
		const milesPerMeter = 0.000621371
		miles := int(meters * milesPerMeter)
		return fmt.Sprintf("%d miles", miles)

	case unitsKilometers:
		return fmt.Sprintf("%d km", int(meters/1000))
	}

	panic("should not be reached")
}
