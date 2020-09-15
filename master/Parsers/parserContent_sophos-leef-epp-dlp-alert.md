#### Parser Content
```Java
{
Name = sophos-leef-epp-dlp-alert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = QRadar
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"	
  Conditions = [ """LEEF:1.0|Sophos|Enterprise Console|""","""|Data control - Alert only|""" ]
  Fields = [ """({host}[^\s]+)\s+LEEF:1.0"""
          """devTime=({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})""",
          """ComputerName=({dest_host}.+?)\s+(\w+=|$)""",
          """LEEF:[^|]*\|Sophos\|Enterprise Console\|[^|]*\|({alert_type}[^|]*)\|""",
          """ReportingName=({alert_name}.+?)\s+(\w+=|$)""",
          """EventID=({alert_id}\d+)""",
          """usrName=[^\\]*\\({user}.+?)\s+(\w+=|$)""",
          """src=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
          """domain=({domain}.+?)\s+(\w+=|$)""",
          """FileName=({file_name}.+?)\s+(\w+=|$)""",
          """FileSize=({bytes}\d+)""",
          """DestinationValue=({target}.+?)\s+(\w+=|$)""",
          ]
}
```