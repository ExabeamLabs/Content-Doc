#### Parser Content
```Java
{
Name = s-cyberark-activity-1
  DataType = "remote-logon"
  Conditions = [ """|Window Title|""", """|Operating System|""" ]
  Fields = ${CyberArkParserTemplates.cyberark-events-1.Fields} [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[^\s]{1,2000})\s{1,100}\|({user}[^\|]{1,2000})"""
    ]
 
cyberark-events-1 {
  Vendor = CyberArk
  Product = CyberArk Vault
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Fields = [
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)\s{1,100}({host}[^\s]{1,2000})"""
    """Protocol=({protocol}[^\s;]{1,2000})""",
    """SessionID=({session_id}[^\s;]{1,2000})""",
    """SrcHost=({src_host}[^\s;]{1,2000})""",
    """User=(({domain}[^\\]{0,2000}?)\\+)?({user}[^\s;]{1,2000})""",
    """Command=({command}[^\s;,]{1,2000})""",
    """ProcessName =({process_name}[^\s;,]{1,2000})""",
    """DstHost=({dest_host}[^\s;,]{1,2000})""",
    
}
```