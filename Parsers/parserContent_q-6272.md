#### Parser Content
```Java
{
Name = q-6272
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = QRadar
  DataType = "windows-nac-logon"
  TimeFormat =  "epoch_sec"
  Conditions = [ """EventIDCode=6272""", """Network Policy Server granted access to a user""" ]
  Fields = [
    """TimeGenerated=({time}\d+)""",
    """Message=\s*({event_name}.+?)\.\s+""",
    """EventIDCode=({event_code}\d+)""",
    """Computer=({host}[\w\-.]+)""",
    """User=(|({user}[^\s]+))""",
    """Domain=(|({domain}[^\s]+))""",
    """User:.+?\sAccount Name:\s*(|(?:({user_type}host)/)?(({domain}[^\\\/]+?)[\\\/]+)?({user}.+?))\s*Account Domain:\s*(|({=domain}.+?))\s*Fully Qualified Account Name:(|(({=domain}[^\\\/]+?)[\\\/]+)?({=user}.+?))""",
    """\sCalled Station Identifier:\s*(-|({dest_mac}\w{2}-\w{2}-\w{2}-\w{2}-\w{2}-\w{2})|({dest_ip}[a-fA-F\d.:]+))""",
    """\sCalling Station Identifier:\s*(-|({src_mac}\w{2}-\w{2}-\w{2}-\w{2}-\w{2}-\w{2})|({src_ip}[a-fA-F\d.:]+))""",    
    """\sNAS IPv(4|6) Address:\s*({dest_ip}[a-fA-F\d.:]+)""",
    """\sNAS Identifier:\s*(-|({location}.+?))\s*NAS Port-Type:""",
  ]
}
```