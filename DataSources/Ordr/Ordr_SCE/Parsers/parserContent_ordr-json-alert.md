#### Parser Content
```Java
{
Name = ordr-json-alert
  Vendor = Ordr
  Product = Ordr SCE
  Lms = Direct
  DataType= "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """: WARNING [""", """] The device (""", """) with severity level """, """"dstIp":""", """"peerId":""" ]
  Fields = [
    """"timestamp":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """"srcHost": "([\d\w:]{1,2000}|({host}[^"]{1,2000}))"""",
    """"severityLevel":\s"({alert_severity}[^"]{1,2000})"""",
    """"alarmHash":\s"({md5_sum}[^"]{1,2000})"""",
    """"alarmType":\s"({alert_name}[^"]{1,2000})"""",
    """"alarmCategory":\s"({alert_type}[^"]{1,2000})"""",
    """"dstIp":\s"({dest_ip}[^"]{1,2000})"""",
    """"clientId":\s"({dest_mac}[^"]{1,2000})"""",
    """"dstPort":\s{0,100}({dest_port}\d{1,100})""",
    """"srcPort":\s{0,100}({src_port}\d{1,100})""",
    """"protocol":\s({protocol}\d{1,100})""",
    """"srcIp":\s"({src_ip}[^"]{1,2000})"""",
    """"srcMac":\s"({src_mac}[^"]{1,2000})""""
  ]
}
```