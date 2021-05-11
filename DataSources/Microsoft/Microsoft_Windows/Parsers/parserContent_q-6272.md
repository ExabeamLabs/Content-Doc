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
    """TimeGenerated=({time}\d{1,100})""",
    """Message=\s{0,100}({event_name}.+?)\.\s{1,100}""",
    """EventIDCode=({event_code}\d{1,100})""",
    """Computer=({host}[\w\-.]+)""",
    """User=(|({user}[^\s]+))""",
    """Domain=(|({domain}[^\s]+))""",
    """User:.+?\sAccount Name:\s{0,100}(|(?:({user_type}host)/)?(({domain}[^\\\/]+?)[\\\/]+)?({user}.+?))\s{0,100}Account Domain:\s{0,100}(|({=domain}.+?))\s{0,100}Fully Qualified Account Name:(|(({=domain}[^\\\/]+?)[\\\/]+)?({=user}.+?))""",
    """\sCalled Station Identifier:\s{0,100}(-|({dest_mac}\w{2}-\w{2}-\w{2}-\w{2}-\w{2}-\w{2})|({dest_ip}[a-fA-F\d.:]+))""",
    """\sCalling Station Identifier:\s{0,100}(-|({src_mac}\w{2}-\w{2}-\w{2}-\w{2}-\w{2}-\w{2})|({src_ip}[a-fA-F\d.:]+))""",    
    """\sNAS IPv(4|6) Address:\s{0,100}({dest_ip}[a-fA-F\d.:]+)""",
    """\sNAS Identifier:\s{0,100}(-|({location}.+?))\s{0,100}NAS Port-Type:""",
  ]
}
```