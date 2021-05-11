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
  Fields = [ """({host}[^\s]+)\s{1,100}LEEF:1.0"""
          """devTime=({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})""",
          """ComputerName=({dest_host}.+?)\s{1,100}(\w+=|$)""",
          """LEEF:[^|]*\|Sophos\|Enterprise Console\|[^|]*\|({alert_type}[^|]*)\|""",
          """ReportingName=({alert_name}.+?)\s{1,100}(\w+=|$)""",
          """EventID=({alert_id}\d{1,100})""",
          """usrName=[^\\]*\\({user}.+?)\s{1,100}(\w+=|$)""",
          """src=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
          """domain=({domain}.+?)\s{1,100}(\w+=|$)""",
          """FileName=({file_name}.+?)\s{1,100}(\w+=|$)""",
          """FileSize=({bytes}\d{1,100})""",
          """DestinationValue=({target}.+?)\s{1,100}(\w+=|$)""",
          ]
}
```