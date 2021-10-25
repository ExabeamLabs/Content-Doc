#### Parser Content
```Java
{
Name = observeit-sessions
  Vendor = ObserveIT
  Product = ObserveIT
  Lms = Direct
  DataType = "remote-logon"
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """EventName=ObserveIT-Sessions;""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """({host}\S+)\s{1,100}(\S+\s{1,100}){4}EventName=""",
    """\sSessionDate=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sOS=({os}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sSessionID=({session_id}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sServerName=({dest_host}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sDomainName=({domain}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sUserName=(?:n\/a|({user}[^;]{1,2000}?))\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sLoginName=({user}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
    """\sClientAddress=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sViewerURL=({additional_info}[^;]{1,2000}?)\s{0,100}(;|"{0,20}\s{0,100}$)""",
  ]
}
```