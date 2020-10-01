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
    """"timestamp":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"srcHost": "([\d\w:]+|({host}[^"]+))"""",
    """"severityLevel":\s"({alert_severity}[^"]+)"""",
    """"alarmHash":\s"({md5_sum}[^"]+)"""",
    """"alarmType":\s"({alert_name}[^"]+)"""",
    """"alarmCategory":\s"({alert_type}[^"]+)"""",
    """"dstIp":\s"({dest_ip}[^"]+)"""",
    """"clientId":\s"({dest_mac}[^"]+)"""",
    """"dstPort":\s*({dest_port}\d+)""",
    """"srcPort":\s*({src_port}\d+)""",
    """"protocol":\s({protocol}\d+)""",
    """"srcIp":\s"({src_ip}[^"]+)"""",
    """"srcMac":\s"({src_mac}[^"]+)""""
  ]
}
```