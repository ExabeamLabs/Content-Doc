#### Parser Content
```Java
{
Name = observeit-useractivity
  Vendor = ObserveIT
  Product = ObserveIT
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """EventName=ObserveIT-UserActivity;""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}\S+)\s{1,100}(\S+\s{1,100}){4}EventName=""",
    """\sActivityTime=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sSessionID=({session_id}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sOS=({os}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sServerName=({dest_host}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sDomainName=({domain}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sUserName=(?:n\/a|({user}[^;]{1,2000}?))\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sLoginName=({user}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sClientName=(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[^;]{1,2000}?))\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sClientAddress=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sProcessName=({process_name}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sViewerURL=({additional_info}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
  ]
}
```