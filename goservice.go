package main

import (
	"log"

	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/kardianos/service"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type LogForUser struct {
	AcceptedPublicKey            int
	AcceptedPassword             int
	FailedPassword               int
	FailedPasswordAndInvalidUser int
	InvalidUser                  int
	Sudo                         int
	SudoUserNOTinSudoers         int
	SudoIncorrectPassword        int
	NewUser                      int
}

func ParseLog(ln string) {

	var usr string

	//	fmt.Println("String")
	//	fmt.Print(ln)

	if strings.Contains(ln, "Accepted publickey") {
		re := regexp.MustCompile(`(\bfor\s)(\w+)`)
		usr = re.FindString(ln)
		usr = strings.TrimPrefix(usr, "for ")
		//	fmt.Println(usr)

		value, ok := m[usr]
		//	fmt.Println(ok)

		if ok {
			value.AcceptedPublicKey += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		} else {
			m[usr] = LogForUser{0, 0, 0, 0, 0, 0, 0, 0, 0}
			//			fmt.Println(m[usr])
			value = m[usr]
			value.AcceptedPublicKey += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		}
	}

	if strings.Contains(ln, "Accepted password") {
		re := regexp.MustCompile(`(\bfor\s)(\w+)`)
		usr = re.FindString(ln)
		usr = strings.TrimPrefix(usr, "for ")
		//		fmt.Println(usr)
		value, ok := m[usr]
		//		fmt.Println(ok)

		if ok {
			value.AcceptedPassword += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		} else {
			m[usr] = LogForUser{0, 0, 0, 0, 0, 0, 0, 0, 0}
			//			fmt.Println(m[usr])
			value = m[usr]
			value.AcceptedPassword += 1
			m[usr] = value
			//			fmt.Println(m[usr])

		}
	}

	if strings.Contains(ln, "Failed password for invalid user") {
		re := regexp.MustCompile(`(\buser\s)(\w+)`)
		usr = re.FindString(ln)
		usr = strings.TrimPrefix(usr, "user ")
		//		fmt.Println(usr)

		value, ok := m[usr]
		//		fmt.Println(ok)

		if ok {
			value.FailedPasswordAndInvalidUser += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		} else {
			m[usr] = LogForUser{0, 0, 0, 0, 0, 0, 0, 0, 0}
			//			fmt.Println(m[usr])
			value = m[usr]
			value.FailedPasswordAndInvalidUser += 1
			m[usr] = value
			//			fmt.Println(m[usr])

		}
	} else if strings.Contains(ln, "Failed password") {
		re := regexp.MustCompile(`(\bfor\s)(\w+)`)
		usr = re.FindString(ln)
		usr = strings.TrimPrefix(usr, "for ")
		//		fmt.Println(usr)

		value, ok := m[usr]
		//		fmt.Println(ok)

		if ok {
			value.FailedPassword += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		} else {
			m[usr] = LogForUser{0, 0, 0, 0, 0, 0, 0, 0, 0}
			//			fmt.Println(m[usr])
			value = m[usr]
			value.FailedPassword += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		}

	}

	if strings.Contains(ln, "user NOT in sudoers") {
		re := regexp.MustCompile(`(\bsudo:\s+)(\w+)`)
		usr = re.FindString(ln)
		//		fmt.Println(usr)
		usr = strings.TrimPrefix(usr, "sudo:")
		//		fmt.Println(usr)
		usr = strings.TrimSpace(usr)
		//		fmt.Println(usr)

		value, ok := m[usr]
		//		fmt.Println(ok)

		if ok {
			value.SudoUserNOTinSudoers += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		} else {
			m[usr] = LogForUser{0, 0, 0, 0, 0, 0, 0, 0, 0}
			//			fmt.Println(m[usr])
			value = m[usr]
			value.SudoUserNOTinSudoers += 1
			m[usr] = value
			//			fmt.Println(m[usr])

		}
	} else if strings.Contains(ln, "incorrect password attempt") {
		re := regexp.MustCompile(`(\bsudo:\s+)(\w+)`)
		usr = re.FindString(ln)
		usr = strings.TrimPrefix(usr, "sudo:")
		usr = strings.TrimSpace(usr)
		//		fmt.Println(usr)

		value, ok := m[usr]
		//		fmt.Println(ok)

		if ok {
			value.SudoIncorrectPassword += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		} else {
			m[usr] = LogForUser{0, 0, 0, 0, 0, 0, 0, 0, 0}
			//			fmt.Println(m[usr])
			value = m[usr]
			value.SudoIncorrectPassword += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		}

	} else if strings.Contains(ln, "sudo:") {
		re := regexp.MustCompile(`(\bsudo:\s+)(\w+)`)
		usr = re.FindString(ln)
		usr = strings.TrimPrefix(usr, "sudo:")
		usr = strings.TrimSpace(usr)
		//		fmt.Println(usr)

		value, ok := m[usr]
		//		fmt.Println(ok)

		if ok {
			value.Sudo += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		} else {
			m[usr] = LogForUser{0, 0, 0, 0, 0, 0, 0, 0, 0}
			//			fmt.Println(m[usr])
			value = m[usr]
			value.Sudo += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		}

	}

	if strings.Contains(ln, "Invalid user") {
		re := regexp.MustCompile(`(\buser\s)(\w+)`)
		usr = re.FindString(ln)
		usr = strings.TrimPrefix(usr, "user ")
		//		fmt.Println(usr)

		value, ok := m[usr]
		//		fmt.Println(ok)

		if ok {
			value.InvalidUser += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		} else {
			m[usr] = LogForUser{0, 0, 0, 0, 0, 0, 0, 0, 0}
			//			fmt.Println(m[usr])
			value = m[usr]
			value.InvalidUser += 1
			m[usr] = value
			//			fmt.Println(m[usr])

		}
	}

	if strings.Contains(ln, "new user:") {
		re := regexp.MustCompile(`(\bname=)(\w+)`)
		usr = re.FindString(ln)
		usr = strings.TrimPrefix(usr, "name=")
		//		fmt.Println(usr)

		value, ok := m[usr]
		//		fmt.Println(ok)

		if ok {
			value.NewUser += 1
			m[usr] = value
			//			fmt.Println(m[usr])
		} else {
			m[usr] = LogForUser{0, 0, 0, 0, 0, 0, 0, 0, 0}
			//			fmt.Println(m[usr])
			value = m[usr]
			value.NewUser += 1
			m[usr] = value
			//			fmt.Println(m[usr])

		}
	}

}

var (
	EventsAuth = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "type_events_count",
			Help: "Type events in auth.log.",
		},
		[]string{"typeevents"},
	)

	EventsAuthUsers = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "type_events_count_for_user",
			Help: "Type events in auth.log for users.",
		},
		[]string{"user", "typeevents"},
	)
)

func init() {
	// Metrics have to be registered to be exposed:
	prometheus.MustRegister(EventsAuth)
	prometheus.MustRegister(EventsAuthUsers)
}

func readFileWithReadString(fn string) (err error) {

	file, err := os.Open(fn)
	defer file.Close()

	if err != nil {
		return err
	}

	// Start reading from the file with a reader.
	reader := bufio.NewReader(file)

	var line string

	for {
		line, err = reader.ReadString('\n')

		ParseLog(line)

		if err != nil {
			break
		}
	}

	if err != io.EOF {
		fmt.Printf(" > Failed!: %v\n", err)
	}

	return
}

var m map[string]LogForUser

func recordMetrics() {
	go func() {
		for {
			m = make(map[string]LogForUser)

			readFileWithReadString("C:\\Programs\\auth.log")

			EventsAuth.Reset()
			EventsAuthUsers.Reset()

			var AcceptedPublicKeyAllUsers int
			var AcceptedPasswordAllUsers int
			var FailedPasswordAllUsers int
			var FailedPasswordAndInvalidUserAllUsers int
			var InvalidUserAllUsers int
			var SudoAllUsers int
			var SudoUserNOTinSudoersAllUsers int
			var SudoIncorrectPasswordAllUsers int
			var NewUserAllUsers int

			for k, v := range m {

				AcceptedPublicKeyAllUsers += v.AcceptedPublicKey
				AcceptedPasswordAllUsers += v.AcceptedPassword
				FailedPasswordAllUsers += v.FailedPassword
				FailedPasswordAndInvalidUserAllUsers += v.FailedPasswordAndInvalidUser
				InvalidUserAllUsers += v.InvalidUser
				SudoAllUsers += v.Sudo
				SudoUserNOTinSudoersAllUsers += v.SudoUserNOTinSudoers
				SudoIncorrectPasswordAllUsers += v.SudoIncorrectPassword
				NewUserAllUsers += v.NewUser

				EventsAuthUsers.WithLabelValues(k, "AcceptedPublicKey").Add(float64(v.AcceptedPublicKey))
				EventsAuthUsers.WithLabelValues(k, "AcceptedPassword").Add(float64(v.AcceptedPassword))
				EventsAuthUsers.WithLabelValues(k, "FailedPassword").Add(float64(v.FailedPassword))
				EventsAuthUsers.WithLabelValues(k, "FailedPasswordAndInvalidUser").Add(float64(v.FailedPasswordAndInvalidUser))
				EventsAuthUsers.WithLabelValues(k, "InvalidUser").Add(float64(v.InvalidUser))
				EventsAuthUsers.WithLabelValues(k, "Sudo").Add(float64(v.Sudo))
				EventsAuthUsers.WithLabelValues(k, "SudoUserNOTinSudoers").Add(float64(v.SudoUserNOTinSudoers))
				EventsAuthUsers.WithLabelValues(k, "SudoIncorrectPassword").Add(float64(v.SudoIncorrectPassword))
				EventsAuthUsers.WithLabelValues(k, "NewUser").Add(float64(v.NewUser))

				fmt.Printf("key[%s] value[%s]\n", k, v)

			}

			fmt.Printf("AcceptedPublicKey value[%s]\n", AcceptedPublicKeyAllUsers)

			EventsAuth.WithLabelValues("AcceptedPublicKey").Add(float64(AcceptedPublicKeyAllUsers))
			EventsAuth.WithLabelValues("AcceptedPassword").Add(float64(AcceptedPasswordAllUsers))
			EventsAuth.WithLabelValues("FailedPassword").Add(float64(FailedPasswordAllUsers))
			EventsAuth.WithLabelValues("FailedPasswordAndInvalidUser").Add(float64(FailedPasswordAndInvalidUserAllUsers))
			EventsAuth.WithLabelValues("InvalidUser").Add(float64(InvalidUserAllUsers))
			EventsAuth.WithLabelValues("Sudo").Add(float64(SudoAllUsers))
			EventsAuth.WithLabelValues("SudoUserNOTinSudoers").Add(float64(SudoUserNOTinSudoersAllUsers))
			EventsAuth.WithLabelValues("SudoIncorrectPassword").Add(float64(SudoIncorrectPasswordAllUsers))
			EventsAuth.WithLabelValues("NewUser").Add(float64(NewUserAllUsers))

			time.Sleep(5 * time.Minute)
		}
	}()
}

var logger service.Logger

type program struct{}

func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.
	go p.run()
	return nil
}
func (p *program) run() {
	recordMetrics()

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe("192.168.15.193:2112", nil)
}
func (p *program) Stop(s service.Service) error {
	// Stop should not block. Return with a few seconds.
	return nil
}

func main() {
	svcConfig := &service.Config{
		Name:        "GoService",
		DisplayName: "Go Service Auth.log",
		Description: "This is a Go service for auth.log.",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}
	logger, err = s.Logger(nil)
	if err != nil {
		log.Fatal(err)
	}
	err = s.Run()
	if err != nil {
		logger.Error(err)
	}
}
