#### Parser Content
```Java
{
Name = oracle-public-cloud-netflow-connection
  Vendor = Oracle
  Product = Public Cloud
  Lms = Direct
  DataType = "netflow-connection"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ ""","type":"com.oraclecloud.vcn.flowlogs.DataEvent"""", ""","flowid":"""", ""","oracle":{"""", """"compartmentid":"""" ]
  Fields = [
    """"time":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"sourceAddress":"({src_ip}[a-fA-F\d:\.]{1,100})"""",
    """"sourcePort":({src_port}\d{1,100})""",
    """"destinationAddress":"({dest_ip}[a-fA-F\d:\.]{1,100})"""",
    """"destinationPort":({dest_port}\d{1,100})""",
    """"action":"({outcome}[^"]{1,2000})"""",
    """"bytesOut":({bytes_out}\d{1,100})""",
    """"protocolName":"({protocol}[^"]{1,2000})"""",
]


}
```