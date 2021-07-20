#### Parser Content
```Java
{
Name = sophos-leef-epp-usb-activity-2
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = QRadar
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"	
  Conditions = [ """LEEF:1.0|Sophos|Enterprise Console|""","""|Data control - Alert only|""", """DestinationValue=removableStorage""" ]
  Fields = [ """({host}[^\s]{1,2000})\s{1,100}LEEF:1.0"""
          """devTime=({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})""",
          """ComputerName=({dest_host}.+?)\s{1,100}(\w+=|$)""",
          """LEEF:[^|]{0,2000}\|Sophos\|Enterprise Console\|[^|]{0,2000}\|({activity}[^|]{0,2000})\|""",
          """usrName=[^\\]{0,2000}\\({user}.+?)\s{1,100}(\w+=|$)""",
          """src=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
          """domain=({domain}.+?)\s{1,100}(\w+=|$)""",
          """FileName=({file_name}.+?)\s{1,100}(\w+=|$)""",
          """FileSize=({bytes}\d{1,100})"""
          ]
}
```