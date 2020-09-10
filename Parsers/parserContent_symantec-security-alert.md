#### Parser Content
```Java
{
Name = symantec-security-alert
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """type":"""", ""","virusSrc":"""", ""","virusName":"""" ]
  Fields = [
    """\d+-\d+-\d+T\d+:\d+:\d+\.\d+[\+\-]\d+:\d+\s+({host}[\w\-.]+)\s""",
    """"@timestamp":"({time}\d+-\d+-\d+T\d+:\d+:\d+\.\d+Z)""",
    """"srcHostname":"({src_host}[^"]+)""",
    """"srcIP":"(0.0.0.0|({src_ip}[A-Fa-f:\d.]+))""",
    """"virusSrc":"({alert_type}[^"]+)""",
    """"filePath":"(Unavailable|({malware_url}[^"]+))""",
    """"virusName":"({alert_name}[^"]+)""",
    """"userID":"(system|({user}[^"]+))""",
    """"action":"({outcome}[^"]+)""",
  ]
}
```