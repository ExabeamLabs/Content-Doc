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
    """\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}[\+\-]\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s""",
    """"@timestamp":"({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}\.\d{1,100}Z)""",
    """"srcHostname":"({src_host}[^"]{1,2000})""",
    """"srcIP":"(0.0.0.0|({src_ip}[A-Fa-f:\d.]{1,2000}))""",
    """"virusSrc":"({alert_type}[^"]{1,2000})""",
    """"filePath":"(Unavailable|({malware_url}[^"]{1,2000}))""",
    """"virusName":"({alert_name}[^"]{1,2000})""",
    """"userID":"(system|({user}[^"]{1,2000}))""",
    """"action":"({outcome}[^"]{1,2000})""",
  ]
}
```