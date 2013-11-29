package main

import (
    "fmt"
    "time"
    "os"
    "bufio"
//    "io"
//    "os/exec"
    "flag"
//    "strconv"
    "crypto/sha256"
    "encoding/base64"
//    "sync"
)

var channel = make(chan uint32)
var hasher = sha256.New()
var bv = []byte("chboing")

func doUntil(doit func(), durationInMs time.Duration) {
	result := uint32(0)
  stop   := time.After(durationInMs)
  for {
    select {
      case <-stop:
          fmt.Println("Stopping!")
          channel <- result
          return
      default:
      	doit()
        result += 1
    }
  }
}


func writeLines(lines []string, path string) error {
  file, err := os.Create(path)
  if err != nil {
    return err
  }
  defer file.Close()

  w := bufio.NewWriter(file)
  for _, line := range lines {
    fmt.Fprintln(w, line)
  }
  return w.Flush()
}

func main() {
  defaultDuration, _ := time.ParseDuration("1000ms")
  outputFile := flag.String("o", "out.txt", "the output file")
  duration := flag.Duration("d", defaultDuration, "the duration")

  flag.Parse()

  fmt.Printf("SHA256 bench: CPU Mono - duration %v\n", *duration)

  go doUntil(func() {
		hasher.Write(bv)
	}, *duration)

  nb := <-channel

  base64.URLEncoding.EncodeToString(hasher.Sum(nil))

  fmt.Printf("Total computed: %d \n", nb)

  writeLines([]string{fmt.Sprintf("%d", nb)}, *outputFile)
}

