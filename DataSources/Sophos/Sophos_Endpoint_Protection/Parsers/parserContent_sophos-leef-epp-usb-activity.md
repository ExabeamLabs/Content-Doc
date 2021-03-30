#### Parser Content
```Java
{
Name = sophos-leef-epp-usb-activity
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = QRadar
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"	
  Conditions = [ """LEEF:1.0|Sophos|Enterprise Console|""","""|Device control - Alert only|""" ]
  Fields = [
          """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
          """devTime=({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})""",
          """ComputerName=({dest_host}.+?)\s+(\w+=|$)""",
          """LEEF:[^|]*\|Sophos\|Enterprise Console\|[^|]*\|({activity}[^|]*)\|""",
          """usrName=[^\\]*\\({user}.+?)\s+(\w+=|$)""",
          """src=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
          """domain=({domain}.+?)\s+(\w+=|$)""",
          """DeviceID=(?:\s|({device_id}.+?))\s+(\w+=|$)""",
          """Model=(?:\s|({device_type}.+?))\s+(\w+=|$)"""
          ]
}
```