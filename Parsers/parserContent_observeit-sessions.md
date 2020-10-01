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
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}\S+)\s+(\S+\s+){4}EventName=""",
    """\sSessionDate=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sOS=({os}[^;]+?)\s*(;|"*\s*$)""",
    """\sSessionID=({session_id}[^;]+?)\s*(;|"*\s*$)""",
    """\sServerName=({dest_host}[^;]+?)\s*(;|"*\s*$)""",
    """\sDomainName=({domain}[^;]+?)\s*(;|"*\s*$)""",
    """\sUserName=(?:n\/a|({user}[^;]+?))\s*(;|"*\s*$)""",
    """\sLoginName=({user}[^;]+?)\s*(;|"*\s*$)""",
    """\sClientAddress=({src_ip}[a-fA-F\d.:]+)""",
    """\sViewerURL=({additional_info}[^;]+?)\s*(;|"*\s*$)""",
  ]
}
```