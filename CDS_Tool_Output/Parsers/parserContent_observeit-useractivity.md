#### Parser Content
```Java
{
Name = observeit-useractivity
  Vendor = ObserveIT
  Lms = Direct
  DataType = "process-created"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """EventName=ObserveIT-UserActivity;""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}\S+)\s+(\S+\s+){4}EventName=""",
    """\sActivityTime=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sSessionID=({session_id}[^;]+?)\s*(;|"*\s*$)""",
    """\sOS=({os}[^;]+?)\s*(;|"*\s*$)""",
    """\sServerName=({dest_host}[^;]+?)\s*(;|"*\s*$)""",
    """\sDomainName=({domain}[^;]+?)\s*(;|"*\s*$)""",
    """\sUserName=(?:n\/a|({user}[^;]+?))\s*(;|"*\s*$)""",
    """\sLoginName=({user}[^;]+?)\s*(;|"*\s*$)""",
    """\sClientName=(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[^;]+?))\s*(;|"*\s*$)""",
    """\sClientAddress=({src_ip}[a-fA-F\d.:]+)""",
    """\sProcessName=({process_name}[^;]+?)\s*(;|"*\s*$)""",
    """\sViewerURL=({additional_info}[^;]+?)\s*(;|"*\s*$)""",
  ]
}
```