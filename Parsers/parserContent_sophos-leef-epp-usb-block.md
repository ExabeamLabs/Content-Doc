#### Parser Content
```Java
{
Name = sophos-leef-epp-usb-block
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = QRadar
  DataType = "dlp-alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"	
  Conditions = [ """LEEF:1.0|Sophos|Enterprise Console|""","""|Device control - Blocked|""" ]
  Fields = [
          """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
          """EventID=({alert_id}[\d]+)""",
          """devTime=({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})""",
          """LEEF:[^|]*\|Sophos\|Enterprise Console\|[^|]*\|({alert_name}[^|]*)\|""",
          """Model=({alert_type}.+?)\s+(\w+=|$)""",
          """usrName=[^\\]*\\({user}.+?)\s+(\w+=|$)""",
          """ComputerName=({dest_host}.+?)\s+(\w+=|$)""",
          """src=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
          """domain=({domain}.+?)\s+(\w+=|$)""",
          """DeviceID=(?:\s|({device_id}.+?))\s+(\w+=|$)""",
          """ActionName=({outcome}.+?)\s+(?:\w+=|$)"""
  ]
}
```