#### Parser Content
```Java
{
Name = cef-logrhythm-process-created
    Vendor = LogRhythm
    Product = LogRhythm
    Lms = Direct
    DataType = "process-created"
    TimeFormat = "MM/dd/yyyy HH:mm:ss"
    Conditions = ["""TIMESTAMP=""", """PNAME=""", """PID=""" ]
    Fields = [
      """TIMESTAMP=({time}\d+\/\d+\/\d\d\d\d\s\d+:\d+:\d+)""",
      """EVENT=({event_name}[^\s]+)""",
      """PID=({process_id}\d+)""",
      """PNAME=({process_name}[^\s]+)""",
      """PROTOCOL=({protocol}[^\s]+)""",
      """ORIGIN=({host}[^\s]+)""",
      """OWNER=(({domain}[^\\]+?)\\+)?({user}[^\s,]+)""",
      """logonusers=(({domain}[^\\]+?)\\+)?({user}[^\s,]+)""",
      """LOCALIP=({src_ip}[A-Fa-f:\d.]+)\sLOCALPORT=({src_port}\d+)\sREMOTEIP=({dest_ip}[A-Fa-f:\d.]+)\sREMOTEPORT=({dest_port}\d+)""",
          ]
}
```