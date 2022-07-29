package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/viper"
)

func errTrat(msg string, err error, data string) bool {
	if err != nil {
		fmt.Println(msg, err)
		return false
	}
	return true
}

func clientTCP(HOST string, PORT string, AUTH string) bool {
	// Parsing the address
	tcpAddr, err := net.ResolveTCPAddr("tcp", HOST+":"+PORT)
	errTrat("Erro na traduçao do host", err, tcpAddr.String())

	//Connecting
	conn, err := net.Dial("tcp", tcpAddr.String())
	errTrat("Erro na Conexão ao host", err, HOST)

	//defer conn.Close()

	//Authenticating
	_, err = conn.Write([]byte("auth " + AUTH))
	errTrat("Erro no token de autenticação", err, AUTH)

	reply := make([]byte, 1024)

	_, err = conn.Read(reply)
	errTrat("Erro na Autenticaçao", err, string(reply))

	//If auth works, sends tensting message
	if strings.Contains(string(reply), "ok") {
		//MSG TEST
		_, err = conn.Write([]byte("Testando"))
		errTrat("Erro Teste", err, "Testando")
		//TEST ANSWER
		_, err = conn.Read(reply)
		errTrat("Erro na Autenticaçao", err, string(reply))
		//CHECK CLOUDWALK PREFIX
		if strings.Contains(string(reply), "CLOUDWALK") {
			return true
		}
	}
	return false
}

func clientHTTP(HOST string, AUTH string) bool {
	resp, err := http.Get(HOST + "?auth=" + AUTH + "&buf=testing")
	errTrat("Erro na conexão HTTP", err, HOST)
	if resp.StatusCode != 200 {
		fmt.Println("Errrrrrrrrrou!!")
	}
	// pegando responsebody em byte
	byteBody, err := io.ReadAll(resp.Body)
	errTrat("Erro no read do body", err, "Body em Byte com sucesso")
	// traduzindo de byte para string
	stringBody := string(byteBody)
	errTrat("Erro na traduçao do byte", err, "Tá em string agora")
	//checando string recebida
	if strings.Contains(stringBody, "CLOUDWALK") {
		return true
	}
	return false
}

var (
	envFile string
)

func initConfig() {

	if envFile != "" {
		viper.SetConfigFile(envFile)
	}

	home, err := os.UserHomeDir()
	errTrat("Nao achou o home", err, "foi")

	viper.AddConfigPath(home)
	viper.SetConfigType("yaml")
	viper.SetConfigName("sre-test")

	viper.AutomaticEnv()

	if err = viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func main() {
	//clientTCP("tonto.cloudwalk.io", "3000", "6eb718f846c6d303ed8054cdf7ccdb18c821de18")
	//clientHTTP("https://tonto-http.cloudwalk.io", "6eb718f846c6d303ed8054cdf7ccdb18c821de18")
	//readConfig("./test.yaml")
	initConfig()
}
