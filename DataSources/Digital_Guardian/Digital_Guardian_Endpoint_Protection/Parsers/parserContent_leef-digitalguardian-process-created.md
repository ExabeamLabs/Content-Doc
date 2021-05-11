#### Parser Content
```Java
{
Name = leef-digitalguardian-process-created
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = QRadar
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """LEEF:""", """|Digital Guardian|Digital Guardian|""", """DigitalGuardian-Events""", """|Application Start|""" ]
  Fields = [
    """devTime=({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
    """({host}[\w\-.]+) LEEF:""",
    """accountName=(({domain}[^\\]+)\\+)?({user}[^\\\s]+?)\s{0,100}(\w+=|$)""",
    """IdentHostName=([^\\]+\\+)?({dest_host}[\w\-.]+?)\s{0,100}(\w+=|$)""",
    """dst=({dest_ip}[A-Fa-f:\d.]+)""",
    """SourceDirectory=({directory}.+?)\s{0,100}(\w+=|$)""",
    """SourceFile=({process_name}.+?)\s{0,100}(\w+=|$)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```