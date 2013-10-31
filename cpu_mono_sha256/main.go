package main

import (
    "fmt"
    "time"
    "os"
    "bufio"
//    "io"
//    "os/exec"
    "flag"
    "strconv"
    "crypto/sha1"
    "encoding/base64"
//    "sync"
)

var channel = make(chan int)
var hasher = sha1.New()
var bv = []byte("chboing")

func doUntil(doit func(), durationInMs time.Duration) {
	result := 0
    stop   := time.After(durationInMs * time.Millisecond)
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
    outputFile := flag.String("o", "out.txt", "the output file")

    flag.Parse()

    go doUntil(func() {
		hasher.Write(bv)
	}, 10000)

    result := <-channel

    hash := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

    writeLines([]string{ strconv.Itoa(result), hash }, *outputFile)

}

