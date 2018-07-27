This docker image uses rsmrr/hilti image and extends it with some network tools. It tests and shows the usage of the IEC-104 parser. 

Build image jjchrom/iec104-hilti:
```bash
cd /path/to/Dockerfile && docker build -t jjchrom/iec104-hilti .
```

Run docker:
```bash
docker run -i -t -v /full/path/to/IEC104_data:/data "jjchrom/iec104-hilti"
```


Test the parser (e.g. inside the docker): 
```
bro -C -r /path/to/pcap_file.pcapng t104.evt t104_lvl_isu.bro 
```
