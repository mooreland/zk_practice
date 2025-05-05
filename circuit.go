package main

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"os"
	"path/filepath"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// Circuit defines a simple circuit
// x**3 + x + 5 == y
type CubicCircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *CubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func CircuitCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "circuit setup with pk,vk",
		Run:   rollupCircuit,
	}
	rollupCircuitFlags(cmd)

	return cmd
}

func rollupCircuitFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("path", "p", ".", "path to place file, defult .")
	cmd.Flags().StringP("filename", "f", "zk", "file name, default zk")
	//cmd.Flags().Uint32P("raw", "r", 0, "create raw or compressed point option, default compressed")
	//cmd.MarkFlagRequired("filename")
}

func rollupCircuit(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("path")
	fileName, _ := cmd.Flags().GetString("filename")
	//raw, _ := cmd.Flags().GetUint32("raw")
	var circuit CubicCircuit
	_, err := createZkKeyFile(&circuit, path, fileName)
	if err != nil {
		fmt.Println("err", err)
		return
	}

	//fmt.Println(vk.Data)
}

func ProofCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "proof",
		Short: "get proof",
		Run:   proof,
	}
	proofFlags(cmd)

	return cmd
}

func proofFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("path", "p", ".", "path to place file, defult .")
	cmd.Flags().StringP("filename", "f", "zk", "file name, default zk")
	cmd.Flags().Uint32P("witness", "w", 3, "witness input")
	cmd.Flags().Uint32P("public", "i", 35, "public input")
	//cmd.MarkFlagRequired("filename")
}

func proof(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("path")
	filename, _ := cmd.Flags().GetString("filename")
	witness, _ := cmd.Flags().GetUint32("witness")
	public, _ := cmd.Flags().GetUint32("public")

	_, err := createProof(path, filename, witness, public)
	if err != nil {
		fmt.Println("err", err)
		return
	}

}

func VerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "verify proof with public input",
		Run:   verify,
	}
	verifyFlags(cmd)

	return cmd
}

func verifyFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("path", "p", ".", "path to place file, defult .")
	cmd.Flags().StringP("filename", "f", "zk", "verify key file name, default zk")
	cmd.Flags().Uint32P("public", "i", 0, "public input")
	cmd.MarkFlagRequired("public")
}

func verify(cmd *cobra.Command, args []string) {
	path, _ := cmd.Flags().GetString("path")
	fileName, _ := cmd.Flags().GetString("filename")
	public, _ := cmd.Flags().GetUint32("public")
	_, err := verifyProof(path, fileName, public)
	if err != nil {
		fmt.Println("err", err)
		return
	}

}

func createZkKeyFile(circuit frontend.Circuit, path, fileName string) (*string, error) {
	//var circuit prove.ZkRollupCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, errors.Wrapf(err, "compile")
	}

	pkName := fileName + ".pk"
	vkName := fileName + ".vk"

	var bufPk, bufVk bytes.Buffer
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, errors.Wrapf(err, "setup")
	}

	//使用WriteTo,可以缩小一半vk大小，但是偶尔会有读取时候可能没有解压缩，证明会失败的情况
	pk.WriteTo(&bufPk)
	vk.WriteTo(&bufVk)

	//if raw != 0 {
	//	pk.WriteRawTo(&bufPk)
	//	vk.WriteRawTo(&bufVk)
	//} else {
	//	pk.WriteTo(&bufPk)
	//	vk.WriteTo(&bufVk)
	//}

	pkfile := filepath.Join(path, pkName)
	fPk, err := os.Create(pkfile)
	if err != nil {
		return nil, errors.Wrapf(err, "create pk file")
	}
	//fPk.WriteString(hex.EncodeToString(bufPk.Bytes()))
	fPk.Write(bufPk.Bytes())
	fPk.Close()

	file := filepath.Join(path, vkName)
	fVk, err := os.Create(file)
	if err != nil {
		return nil, errors.Wrapf(err, "create vk file")
	}
	//fVk.WriteString(hex.EncodeToString(bufVk.Bytes()))
	fVk.Write(bufVk.Bytes())
	fVk.Close()

	return nil, nil
}

func createProof(path, fileName string, witnessVal, pubVal uint32) (*string, error) {
	var circuit CubicCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, errors.Wrapf(err, "compile")
	}

	file := filepath.Join(path, fileName+".pk")
	bufPk, err := readFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "read pkfile")
	}
	var pk groth16_bn254.ProvingKey
	pk.ReadFrom(bufPk)

	file = filepath.Join(path, fileName+".vk")
	bufVk, err := readFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "read vkfile")
	}
	var vk groth16_bn254.VerifyingKey
	vk.ReadFrom(bufVk)

	assignment := CubicCircuit{X: witnessVal, Y: pubVal}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, &pk, witness)
	var bufProof bytes.Buffer
	_, err = proof.WriteTo(&bufProof)
	if err != nil {
		return nil, errors.Wrapf(err, "write to buff")
	}

	file = filepath.Join(path, "proof")
	fProof, err := os.Create(file)
	if err != nil {
		return nil, errors.Wrapf(err, "create proof")
	}
	defer fProof.Close()
	fProof.Write(bufProof.Bytes())

	return nil, nil
}

func verifyProof(path, fileName string, pubVal uint32) (*string, error) {
	file := filepath.Join(path, fileName+".vk")
	bufVk, err := readFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "read vkfile")
	}
	var vk groth16_bn254.VerifyingKey
	vk.ReadFrom(bufVk)

	file = filepath.Join(path, "proof")
	bufProof, err := readFile(file)
	if err != nil {
		return nil, errors.Wrapf(err, "read proof file")
	}

	var proof groth16_bn254.Proof
	proof.ReadFrom(bufProof)

	assignment := CubicCircuit{X: 0, Y: pubVal}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	err = groth16.Verify(&proof, &vk, publicWitness)
	if err != nil {
		return nil, errors.Wrapf(err, "verify")
	}
	return nil, nil
}

func readFile(file string) (*bytes.Buffer, error) {
	// open file
	f, err := os.Open(file)
	if err != nil {
		return nil, errors.Wrapf(err, "readfile")
	}
	defer f.Close()

	//文件内容在写的时候已经编码，直接读取，不需要编码成字符串
	var buff bytes.Buffer
	buff.ReadFrom(f)
	return &buff, nil
}
