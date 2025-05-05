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

	//// compiles our circuit into a R1CS
	//var circuit CubicCircuit
	//ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	//
	//// groth16 zkSNARK: Setup
	//pk, vk, _ := groth16.Setup(ccs)
	//
	// witness definition
	//assignment := CubicCircuit{X: 3, Y: 35}
	//witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	//publicWitness, _ := witness.Public()
	//
	//// groth16: Prove & Verify
	//proof, _ := groth16.Prove(ccs, pk, witness)
	//groth16.Verify(proof, vk, publicWitness)
}

//func main() {
//    //circuit := Circuit{X:3,Y:35}
//    var ct Circuit
//    //ct.Y.Assign(35)
//    //ct.X = frontend.Value(3)
//
//    _,err := createZkKeyFile(&ct,".","cube",0,1)
//    if err != nil {
//        fmt.Println("err=",err)
//    }
//    fmt.Println("Hello, Go project!")
//}
