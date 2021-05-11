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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """"srcHost": "([\d\w:]+|({host}[^"]+))"""",
    """"severityLevel":\s"({alert_severity}[^"]+)"""",
    """"alarmHash":\s"({md5_sum}[^"]+)"""",
    """"alarmType":\s"({alert_name}[^"]+)"""",
    """"alarmCategory":\s"({alert_type}[^"]+)"""",
    """"dstIp":\s"({dest_ip}[^"]+)"""",
    """"clientId":\s"({dest_mac}[^"]+)"""",
    """"dstPort":\s{0,100}({dest_port}\d{1,100})""",
    """"srcPort":\s{0,100}({src_port}\d{1,100})""",
    """"protocol":\s({protocol}\d{1,100})""",
    """"srcIp":\s"({src_ip}[^"]+)"""",
    """"srcMac":\s"({src_mac}[^"]+)""""
  ]
}
```