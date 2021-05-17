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
          """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
          """EventID=({alert_id}[\d]{1,2000})""",
          """devTime=({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})""",
          """LEEF:[^|]{0,2000}\|Sophos\|Enterprise Console\|[^|]{0,2000}\|({alert_name}[^|]{0,2000})\|""",
          """Model=({alert_type}.+?)\s{1,100}(\w+=|$)""",
          """usrName=[^\\]{0,2000}\\({user}.+?)\s{1,100}(\w+=|$)""",
          """ComputerName=({dest_host}.+?)\s{1,100}(\w+=|$)""",
          """src=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
          """domain=({domain}.+?)\s{1,100}(\w+=|$)""",
          """DeviceID=(?:\s|({device_id}.+?))\s{1,100}(\w+=|$)""",
          """ActionName=({outcome}.+?)\s{1,100}(?:\w+=|$)"""
  ]
}
```