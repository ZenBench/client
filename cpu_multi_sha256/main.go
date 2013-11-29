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
    "hash"
    //"encoding/base64"
    "sync"
)

func doUntil(idx int, channel chan<- uint32, doit func(int), durationInMs time.Duration) {
	result := uint32(0)
  stop   := time.After(durationInMs)
  for {
    select {
      case <-stop:
          channel <- result
          return
      default:
      	doit(idx)
        //fmt.Println("after doit")
        result += uint32(1)
    }
  }
}

func worker(wg *sync.WaitGroup, idx int, receiver chan<- uint32, init func(int), doit func(int), durationInMs time.Duration) {
    // Decreasing internal counter for wait-group as soon as goroutine finishes
    defer wg.Done()

    init(idx)
    doUntil(idx, receiver, doit, durationInMs)
}

func monitorWorker(wg *sync.WaitGroup, receiver chan uint32) {
  wg.Wait()
  close(receiver)
}

func reduceWorker(receiver <-chan uint32, reducer chan<- uint32) {
  result := uint32(0)
  for i:= range receiver {
    result += i
  }
  reducer <- result
}

func launchWorkers(nb int, durationInMs time.Duration, init func(int), doit func(int)) uint32 {
    receiver := make(chan uint32)
    wg := new(sync.WaitGroup)

    // Adding routines to workgroup and running then
    for i := 0; i < nb; i++ {
        wg.Add(1)
        go worker(wg, i, receiver, init, doit, durationInMs)
    }

    go monitorWorker(wg, receiver)

    reducer := make(chan uint32)
    go reduceWorker(receiver, reducer)

    return <-reducer
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
  nbThreads := flag.Int("t", 5, "the number of threads")
  duration := flag.Duration("d", defaultDuration, "the duration")

  flag.Parse()

  var hashers []*hash.Hash = make([]*hash.Hash, *nbThreads)
  var bv = []byte("chboing")

  loop := func(idx int) {
    (*hashers[idx]).Write(bv)
  }

  init := func(idx int) {
    t := sha256.New()
    hashers[idx] = &t
  }

  fmt.Printf("SHA256 bench: CPU Multi(%d) - duration %v\n", *nbThreads, *duration)

  nb := launchWorkers(*nbThreads, *duration, init, loop)

  fmt.Printf("Total computed: %d \n", nb)

  writeLines([]string{fmt.Sprintf("%d", nb)}, *outputFile)
}

