package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var (
	rootCmd = &cobra.Command{
		Use:   "prove",
		Short: "create prove env",
	}
)

func init() {
	rootCmd.AddCommand(
		CircuitCmd(),
		ProofCmd(),
		VerifyCmd(),
	)
}

func main() {

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
