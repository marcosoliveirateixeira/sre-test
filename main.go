package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/feeds"
	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type status struct {
	// tcpStatus = make(map[string]bool)
	tcpStatus  string
	httpStatus string
}

var (
	envFile string

	notifyEmail       string
	checkInterval     time.Duration
	timeout           time.Duration
	healthThreshold   int32
	unhealthThreshold int32
	rssFeed           bool
	rssFeedHost       string
	rssFeedPort       string

	tcpHost string
	tcpPort string

	httpHost string

	statusMtx sync.RWMutex
)

var rootCmd = &cobra.Command{
	Use:   "sre-checker",
	Short: "Check status from Tonto services",
	Run: func(cmd *cobra.Command, args []string) {
		actualStatus := status{
			tcpStatus:  "WAITING FOR STATUS",
			httpStatus: "WAITING FOR STATUS",
		}

		counting(cmd, &actualStatus)

		rssServerHost, _ := cmd.Flags().GetString("rss-feed-host")
		rssServerPort, _ := cmd.Flags().GetString("rss-feed-port")
		enableRssServer, _ := cmd.Flags().GetBool("rss-feed")
		if enableRssServer {
			RSS(&actualStatus, rssServerHost, rssServerPort)
		}

	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func errTrat(msg string, err error, data string) bool {
	if err != nil {
		fmt.Println(msg, err)
		return false
	}
	return true
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&envFile, "config", "", "config file (default is $HOME/sre-checker.yaml)")
	rootCmd.PersistentFlags().StringVar(&notifyEmail, "notify-email", "", "Email to get notifications")
	rootCmd.PersistentFlags().DurationVar(&checkInterval, "check-interval", 5*time.Second, "Check interval in seconds")
	rootCmd.PersistentFlags().DurationVarP(&timeout, "timeout", "t", 30*time.Second, "Max timeout from service in seconds")
	rootCmd.PersistentFlags().Int32Var(&healthThreshold, "health-thresold", 5, "Consecutive success")
	rootCmd.PersistentFlags().Int32Var(&unhealthThreshold, "unhealth-thresold", 5, "Consecutive failures")
	rootCmd.PersistentFlags().BoolVar(&rssFeed, "rss-feed", false, "Enable RSS Feed server.")
	rootCmd.PersistentFlags().StringVar(&rssFeedHost, "rss-feed-host", "0.0.0.0", "RSS Feed server host")
	rootCmd.PersistentFlags().StringVar(&rssFeedPort, "rss-feed-port", "80", "RSS Feed server port")

	rootCmd.PersistentFlags().StringVar(&tcpHost, "tcp-host", "", "TCP server host to be track")
	rootCmd.PersistentFlags().StringVar(&tcpPort, "tcp-port", "80", "TCP server port to be track")
	rootCmd.PersistentFlags().StringVar(&httpHost, "http-host", "", "HTTP server host to be track")
}

func initConfig() {

	if envFile != "" {
		viper.SetConfigFile(envFile)
	}

	home, err := os.UserHomeDir()
	errTrat("Nao achou o home", err, "foi")

	viper.AddConfigPath(home)
	viper.AddConfigPath(".")
	viper.SetConfigType("yaml") //se nao tiver extensão
	viper.SetConfigName("conf")

	viper.AutomaticEnv()

	if err = viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
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

func sendEmail(email, service, status string) {

	from := viper.GetString("SMTP_EMAIL")

	user := viper.GetString("SMTP_USER")
	password := viper.GetString("SMTP_PWD")

	to := []string{
		email,
	}

	addr := viper.GetString("SMTP_ADDR")
	host := viper.GetString("SMTP_HOST")
	sender := viper.GetString("SMTP_SENDER")

	msg := []byte("From:" + sender + "\r\n" +
		"To:" + email + "\r\n" +
		"Subject: Checando" + service + " ele está " + status + "\r\n\r\n" +
		"Checkpoint" + service + "está " + status + "\r\n")

	auth := smtp.PlainAuth("", user, password, host)

	err := smtp.SendMail(addr, auth, from, to, msg)

	errTrat("Erro SMTP", err, "Foi")

	fmt.Println("Email sent successfully")
}

func counting(cmd *cobra.Command, status *status) {
	tcpOK := 0
	tcpDOWN := 0
	httpOK := 0
	httpDOWN := 0

	email := viper.GetString("SMTP_EMAIL")
	checkInterval := viper.GetDuration("INTERVAL")
	tcpHost := viper.GetString("TCP_HOST")
	tcpPort := viper.GetString("TCP_PORT")
	httpHost := viper.GetString("HTTP_HOST")
	auth := viper.GetString("TONTO_AUTH")
	healthThresold := viper.GetInt32("HEALTH_THRESOLD")
	unhealthThresold := viper.GetInt32("UNHEALTH_THRESOLD")

	fmt.Println("Starting Tracking...")

	go func() {
		for {
			testResult := clientTCP(tcpHost, tcpPort, auth)

			if testResult {
				tcpOK++
				tcpDOWN = 0
			} else {
				tcpDOWN++
				tcpOK = 0
			}

			if tcpOK >= int(healthThresold) {
				tcpOK = int(healthThresold)
				if status.tcpStatus != "UP" {
					status.tcpStatus = "UP"
					sendEmail(email, "TCP", status.tcpStatus)
				}
			}
			if tcpDOWN >= int(unhealthThresold) {
				tcpDOWN = int(unhealthThresold)
				if status.tcpStatus != "DOWN" {
					status.tcpStatus = "DOWN"
					sendEmail(email, "TCP", status.tcpStatus)
				}
			}
			time.Sleep(checkInterval)
		}
	}()

	go func() {
		for {
			testResult := clientHTTP(httpHost, auth)

			if testResult {
				httpOK++
				httpDOWN = 0
			} else {
				httpDOWN++
				httpOK = 0
			}

			if httpOK >= int(healthThresold) {
				httpOK = int(healthThresold)
				if status.httpStatus != "UP" {
					status.httpStatus = "UP"
					sendEmail(email, "HTTP", status.httpStatus)
				}
			}
			if httpDOWN >= int(unhealthThresold) {
				httpDOWN = int(unhealthThresold)
				if status.httpStatus != "DOWN" {
					status.httpStatus = "DOWN"
					sendEmail(email, "HTTP", status.httpStatus)
				}
			}
			time.Sleep(checkInterval)
		}
	}()

}

func RSS(status *status, host, port string) {
	fmt.Println("Iniciando o Servidor RSS")
	r := mux.NewRouter()
	r.HandleFunc("/", func(res http.ResponseWriter, req *http.Request) {
		now := time.Now()
		feed := &feeds.Feed{
			Title:       "Cloud Walk Monitoring",
			Link:        &feeds.Link{Href: "/"},
			Description: "RSS Feed Monitor",
			Created:     now,
		}

		feed.Add(&feeds.Item{
			Title:       "Tonto TCP Service" + status.tcpStatus,
			Link:        &feeds.Link{Href: "tonto.cloudwalk.io:3000"},
			Description: "Test on TCP Tonto",
			Created:     now,
		})

		feed.Add(&feeds.Item{
			Title:       "Tonto HTTP Service" + status.httpStatus,
			Link:        &feeds.Link{Href: "https://tonto-http.cloudwalk.io"},
			Description: "Test on HTTP Tonto",
			Created:     now,
		})

		rssFeed := (&feeds.Rss{Feed: feed}).RssFeed()
		err := feeds.WriteXML(rssFeed, res)
		errTrat("ERRO no XML", err, "Run!")
	})

	http.ListenAndServe(":3000", r)
}

func main() {
	Execute()
}
