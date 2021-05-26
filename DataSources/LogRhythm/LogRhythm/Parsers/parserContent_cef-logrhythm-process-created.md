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
      """TIMESTAMP=({time}\d{1,100}\/\d{1,100}\/\d\d\d\d\s\d{1,100}:\d{1,100}:\d{1,100})""",
      """EVENT=({event_name}[^\s]{1,2000})""",
      """PID=({process_id}\d{1,100})""",
      """PNAME=({process_name}[^\s]{1,2000})""",
      """PROTOCOL=({protocol}[^\s]{1,2000})""",
      """ORIGIN=({host}[^\s]{1,2000})""",
      """OWNER=(({domain}[^\\]{1,2000}?)\\+)?({user}[^\s,]{1,2000})""",
      """logonusers=(({domain}[^\\]{1,2000}?)\\+)?({user}[^\s,]{1,2000})""",
      """LOCALIP=({src_ip}[A-Fa-f:\d.]{1,2000})\sLOCALPORT=({src_port}\d{1,100})\sREMOTEIP=({dest_ip}[A-Fa-f:\d.]{1,2000})\sREMOTEPORT=({dest_port}\d{1,100})""",
          ]
}
```