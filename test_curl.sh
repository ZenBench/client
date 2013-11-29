curl -XPOST 'POSTURL' -H 'Content-type: application/json' --data-binary '{
  "id": "v1@anonyme",
  "host": "vm126.0x50.net",
  "env": [
    { "types": "cpu", "ref": "Common KVM processor" , "CPU_LOAD": "0.23", "CPU_TYPE": "Common KVM processor", "CPU_MHZ": "2500.024", "CPU_MHZ_2": "2000 MHz", "CPU_NB": "2", "CPU_CACHE": "4096 KB"},
    { "types": "ram", "ref": "RAM--1.0G" , "RAM_TOTAL": "1.0G", "RAM_FREE": "643", "RAM_NBDIM": "1", "RAM_TYPE": "RAM", "RAM_FREQ": ""}
  ],
  "metrics": [
        { "id": "CPU_SHA156", "value": "1380"}

  ]
}'

