#### Parser Content
```Java
{
Name = sophos-leef-epp-virus-alert
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = QRadar
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"	
  Conditions = [ """LEEF:1.0|Sophos|Enterprise Console|""","""|Viruses/spyware""" ]
  Fields = [
             """exabeam_host=(.+?@\s{0,100})?({host}[^\s]+)""",
          """EventID=({alert_id}[\d]+)""",
          """devTime=({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})""",
          """usrName=[^\\]*\\({user}.+?)\s{1,100}(\w+=|$)""",
          """LEEF:[^|]*\|Sophos\|Enterprise Console\|[^|]*\|({alert_name}[^|]*)\|""",
          """ReportingName=({alert_type}.+?)\s{1,100}(\w+=|$)""",
          """ComputerName=({src_host}.+?)\s{1,100}(\w+=|$)""",
          """src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
          """ActionName=({outcome}.*?)\s{1,100}\w+=""", 
  ]
}
```