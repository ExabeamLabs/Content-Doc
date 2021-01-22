#### Parser Content
```Java
{
Name = observeit-dba-activity
  Vendor = ObserveIT
  Lms = Direct
  DataType = "database-access"
  IsHVF = true
  TimeFormat = "MM/dd/yyyy HH:mm:ss"
  Conditions = [ """EventName=ObserveIT-DBA_Activity;""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """({host}\S+)\s+(\S+\s+){4}EventName=""",
    """\sStartTime=({time}\d\d\/\d\d\/\d\d\d\d \d\d:\d\d:\d\d)""",
    """\sOS=({os}[^;]+?)\s*(;|"*\s*$)""",
    """\sSessionID=({session_id}[^;]+?)\s*(;|"*\s*$)""",
    """\sServerName=({dest_host}[^;]+?)\s*(;|"*\s*$)""",
    """\sDomainName=({domain}[^;]+?)\s*(;|"*\s*$)""",
    """\s(?i)ViewerURL=({additional_info}[^;]+?)\s*(;|"*\s*$)""",
    """\sUserName=(?:n\/a|({user}[^;]+?))\s*(;|"*\s*$)""",
    """\sLoginName=({user}[^;]+?)\s*(;|"*\s*$)""",
    """\sSqlDBName=({database_name}[^;]+?)\s*(;|"*\s*$)""",
    """\sSqlUserName=([^;\\]+\\)?({db_user}[^;]+?)\s*(;|"*\s*$)""",
    """\sClientName=(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({src_host}[^;]+?))\s*(;|"*\s*$)""",
    """\sClientAddress=({src_ip}[a-fA-F\d.:]+)""",
    """\sProcessName=({process_name}[^;]+?)\s*(;|"*\s*$)""",
    """\sWindowTitle=({database_objects}[^;\-]+?)\s*\-[^;]*?\-\s*({app}[^;\-]+?)\s*;"""
  ]
  DupFields = [ "user->os_user" , "process_name->service_name"]
}
```